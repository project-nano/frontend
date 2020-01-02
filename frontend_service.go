package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/project-nano/framework"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type FrontEndService struct {
	serviceListener        net.Listener
	frontendServer         http.Server
	listenAddress          string
	backendHost            string
	backendURL             string
	reverseProxy           *httputil.ReverseProxy
	channelManager         *ChannelManager
	sessionManager         *SessionManager
	userManager            *UserManager
	logManager             *LogManager
	userInitialed          bool
	fileHandler            http.Handler
	sortedSignatureHeaders []string
	apiID                  string
	apiKey                 string
	corsEnable             bool
	webRoot                string
	spaPage                string
	runner                 *framework.SimpleRunner
}

type Proxy struct {
	service *FrontEndService
}

const (
	CurrentVersion          = "1.1.3"
	HeaderNameHost          = "Host"
	HeaderNameContentType   = "Content-Type"
	HeaderNameSession       = "Nano-Session"
	HeaderNameDate          = "Nano-Date"
	HeaderNameScope         = "Nano-Scope"
	HeaderNameAuthorization = "Nano-Authorization"
	APIRoot                 = "/api"
	APIVersion              = 1
	CoreAPIRoot             = "/api"
	CoreAPIVersion          = 1
	DefaultPageName         = "index.html"
)


func (proxy *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request){
	proxy.service.routeToDefaultPage(w, r)
}

func saveConfig(config FrontEndConfig, filename string) (err error) {
	var data []byte
	if data, err = json.MarshalIndent(config, "", " "); err != nil{
		err = fmt.Errorf("marshal new config fail: %s", err.Error())
		return
	}
	var file *os.File
	if file, err = os.Create(filename); err != nil{
		err = fmt.Errorf("create new config '%s' fail: %s", filename, err.Error())
		return
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil{
		err = fmt.Errorf("write new config '%s' fail: %s", filename, err.Error())
		return
	}
	return nil
}

func CreateFrontEnd(configPath, dataPath string) (service *FrontEndService, err error ) {
	var configFile = filepath.Join(configPath, ConfigFileName)
	var data []byte
	if data, err = ioutil.ReadFile(configFile); err != nil {
		return
	}
	var config FrontEndConfig
	if err = json.Unmarshal(data, &config); err != nil {
		return
	}
	var configModified = false
	if 0 == len(config.APIID){
		const (
			dummyID  = "dummyID"
			dummyKey = "ThisIsAKeyPlaceHolder_ChangeToYourContent"
		)
		config.APIID = dummyID
		config.APIKey = dummyKey
		log.Printf("<api> warning: dummy API credential '%s' created", dummyID)
		configModified = true
	}else if 0 == len(config.APIKey){
		err = errors.New("API Key required")
		return
	}
	var webRoot = config.WebRoot
	if 0 == len(webRoot){
		var workingPath = filepath.Dir(configPath)
		config.WebRoot = filepath.Join(workingPath, WebRootName)
		webRoot = config.WebRoot
		configModified = true
		log.Printf("<frontend> set default web root path to '%s'", webRoot)
	}
	if _, err = os.Stat(webRoot); os.IsNotExist(err){
		err = fmt.Errorf("web root path %s not exists", webRoot)
		return
	}
	if configModified{
		if err = saveConfig(config, configFile); err != nil{
			log.Printf("<frontend> update config fail: %s", err.Error())
			return
		}
	}

	service = &FrontEndService{}
	service.webRoot = webRoot
	service.apiID = config.APIID
	service.apiKey = config.APIKey
	service.corsEnable = config.CORSEnable
	service.listenAddress = fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort)
	service.serviceListener, err = net.Listen("tcp", service.listenAddress)
	if err != nil{
		return
	}
	service.backendHost = config.ServiceHost
	var proxyTarget = fmt.Sprintf("http://%s:%d", config.ServiceHost, config.ServicePort)
	service.backendURL = fmt.Sprintf("%s%s/v%d", proxyTarget,
		CoreAPIRoot, CoreAPIVersion)
	proxyUrl, err := url.Parse(proxyTarget)
	if err != nil{
		return
	}
	service.reverseProxy = httputil.NewSingleHostReverseProxy(proxyUrl)
	service.channelManager, err = CreateChannelManager()
	if err != nil{
		return
	}
	var router = httprouter.New()
	service.registerHandler(router)
	service.spaPage = filepath.Join(webRoot, DefaultPageName)
	err = filepath.Walk(webRoot, func(path string, info os.FileInfo, previousErr error) error {
		if previousErr != nil{
			return fmt.Errorf("encounter error in path '%s': %s", previousErr.Error())
		}
		if path == webRoot || filepath.Dir(path) != webRoot{
			//ignore root
			return nil
		}
		if info.IsDir(){
			//map path
			var pathName = filepath.Base(path)
			var webPath = fmt.Sprintf("/%s/*filepath", pathName)
			var filePath = filepath.Join(webRoot, pathName)
			//log.Printf("<frontend> debug: mapped path '%s' => '%s'", webPath, filePath)
			router.ServeFiles(webPath, http.Dir(filePath))
		}else{
			//single file
			var filename = filepath.Base(path)
			var fileURl = fmt.Sprintf("/%s", filename)
			//log.Printf("<frontend> debug: mapped file '%s' => '%s'", fileURl, webRoot)
			router.Handle("GET", fileURl, service.mapSingleFile)
		}
		return nil
	})
	if err != nil{
		return
	}
	router.NotFound = &Proxy{service}

	service.frontendServer.Handler = router
	service.runner = framework.CreateSimpleRunner(service.Routine)

	service.userManager, err = CreateUserManager(configPath)
	if err != nil{
		return
	}
	service.sessionManager, err = CreateSessionManager()
	if err != nil{
		return
	}
	if service.logManager, err = CreateLogManager(dataPath); err != nil{
		return
	}
	service.userInitialed = service.userManager.IsUserAvailable()
	service.fileHandler = http.FileServer(http.Dir(webRoot))
	service.sortedSignatureHeaders = []string{
		HeaderNameHost,
		HeaderNameContentType,
		HeaderNameSession,
		HeaderNameDate,
		HeaderNameScope,
	}
	sort.Reverse(sort.StringSlice(service.sortedSignatureHeaders))
	log.Printf("<frontend> CORS %t, web root: %s", service.corsEnable, webRoot)
	return
}

func (service *FrontEndService)GetListenAddress() string{
	return service.listenAddress
}
func (service *FrontEndService)GetBackendURL() string{
	return service.backendURL
}

func (service *FrontEndService) GetVersion() string{
	return CurrentVersion
}

func (service *FrontEndService) Start() error{
	return service.runner.Start()
}

func (service *FrontEndService) Stop() error{
	return service.runner.Stop()
}

func (service *FrontEndService) Routine(c framework.RoutineController){
	log.Printf("<frontend> %s started", CurrentVersion)
	go service.frontendServer.Serve(service.serviceListener)
	service.channelManager.Start()
	service.userManager.Start()
	service.sessionManager.Start()
	service.logManager.Start()

	for !c.IsStopping(){
		select {
		case <- c.GetNotifyChannel():
			log.Println("<frontend> stopping server...")
			service.logManager.Stop()
			service.sessionManager.Stop()
			service.userManager.Stop()
			service.channelManager.Stop()
			c.SetStopping()
			//shutdown server
			ctx, _ := context.WithCancel(context.TODO())
			if err := service.frontendServer.Shutdown(ctx);err != nil{
				log.Printf("<frontsend> shutdown server fail: %s", err.Error())
			}else{
				log.Println("<frontend> server shutdown")
			}

		}
	}

	c.NotifyExit()
}

func (service *FrontEndService)registerHandler(router *httprouter.Router){
	const (
		GET    = "GET"
		POST   = "POST"
		PUT    = "PUT"
		DELETE = "DELETE"
	)

	var redirect = func(r *httprouter.Router, path string, method string) {
		r.Handle(method, mapAPIPath(path), service.redirectToBackend)
	}

	//API
	redirect(router, "/instances/:id", GET)
	redirect(router, "/instances/:id", POST)
	redirect(router, "/instances/:id", DELETE)

	redirect(router, "/guests/:id", GET)
	redirect(router, "/guests/", POST)
	redirect(router, "/guests/:id", DELETE)

	redirect(router, "/guests/:id/cores", PUT)
	redirect(router, "/guests/:id/memory", PUT)
	redirect(router, "/guests/:id/system/", PUT)
	redirect(router, "/guests/:id/qos/cpu", PUT)
	redirect(router, "/guests/:id/qos/disk", PUT)
	redirect(router, "/guests/:id/qos/network", PUT)

	redirect(router, "/guests/:id/name/", PUT)//modify guest name
	redirect(router, "/guests/:id/auth", PUT)
	redirect(router, "/guests/:id/auth", GET)
	redirect(router, "/guests/:id/disks/resize/:index", PUT)
	redirect(router, "/guests/:id/disks/shrink/:index", PUT)

	redirect(router, "/compute_zone_status/", GET)
	redirect(router, "/compute_pool_status/", GET)
	redirect(router, "/compute_pool_status/:pool", GET)
	redirect(router, "/compute_cell_status/:pool", GET)
	redirect(router, "/compute_cell_status/:pool/:cell", GET)
	redirect(router, "/instance_status/:pool", GET)
	redirect(router, "/instance_status/:pool/:cell", GET)

	redirect(router, "/compute_pools/", GET)
	redirect(router, "/compute_pools/:pool", GET)
	redirect(router, "/compute_pools/:pool", POST)
	redirect(router, "/compute_pools/:pool", PUT)
	redirect(router, "/compute_pools/:pool", DELETE)
	redirect(router, "/compute_pool_cells/", GET)
	redirect(router, "/compute_pool_cells/:pool", GET)
	redirect(router, "/compute_pool_cells/:pool/:cell", GET)
	redirect(router, "/compute_pool_cells/:pool/:cell", POST)
	redirect(router, "/compute_pool_cells/:pool/:cell", PUT)
	redirect(router, "/compute_pool_cells/:pool/:cell", DELETE)

	//address pool
	redirect(router, "/address_pools/", GET)
	redirect(router, "/address_pools/:pool", GET)
	redirect(router, "/address_pools/:pool", POST)
	redirect(router, "/address_pools/:pool", PUT)
	redirect(router, "/address_pools/:pool", DELETE)

	//address range
	redirect(router, "/address_pools/:pool/:type/ranges/", GET)
	redirect(router, "/address_pools/:pool/:type/ranges/:start", GET)
	redirect(router, "/address_pools/:pool/:type/ranges/:start", POST)
	redirect(router, "/address_pools/:pool/:type/ranges/:start", DELETE)

	//storage pools
	redirect(router, "/storage_pools/", GET)
	redirect(router, "/storage_pools/:pool", GET)
	redirect(router, "/storage_pools/:pool", POST)
	redirect(router, "/storage_pools/:pool", PUT)
	redirect(router, "/storage_pools/:pool", DELETE)

	redirect(router, "/media_images/", GET)
	redirect(router, "/media_images/", POST)
	redirect(router, "/media_images/:id", GET)
	redirect(router, "/media_images/:id", DELETE)
	redirect(router, "/media_images/:id", PUT)//modify media image info
	redirect(router, "/media_images/:id/file/", POST)

	redirect(router, "/disk_images/", POST)
	redirect(router, "/disk_images/:id", GET)
	redirect(router, "/disk_images/:id", DELETE)
	redirect(router, "/disk_images/:id", PUT) //modify disk image info
	redirect(router, "/disk_images/:id/file/", GET)
	redirect(router, "/disk_images/:id/file/", POST)

	redirect(router, "/instances/:id/media", POST)
	redirect(router, "/instances/:id/media", DELETE)

	redirect(router, "/instances/:id/snapshots/", GET)
	redirect(router, "/instances/:id/snapshots/", POST)
	redirect(router, "/instances/:id/snapshots/", PUT)
	redirect(router, "/instances/:id/snapshots/:name", GET)
	redirect(router, "/instances/:id/snapshots/:name", DELETE)

	//batch
	redirect(router, "/batch/create_guest/", POST)//start batch creating
	redirect(router, "/batch/create_guest/:id", GET)//query batch creating
	redirect(router, "/batch/delete_guest/", POST)//start batch deleting
	redirect(router, "/batch/delete_guest/:id", GET)//query batch deleting
	redirect(router, "/batch/stop_guest/", POST)//start batch stopping
	redirect(router, "/batch/stop_guest/:id", GET)//query batch stopping

	//migrations
	redirect(router, "/migrations/", GET)
	redirect(router, "/migrations/:id", GET)
	redirect(router, "/migrations/", POST)

	//inner function

	//router.GET(mapAPIPath("/"), service.defaultLandingPage)
	//router.GET("/initial.html", service.initialSystem)


	router.GET(mapAPIPath("/monitor_channels/:id"), service.handleEstablishChannel)
	router.POST(mapAPIPath("/monitor_channels/"), service.handleCreateChannel)

	//user roles
	router.GET(mapAPIPath("/roles/"), service.queryRoles)
	router.GET(mapAPIPath("/roles/:role"), service.getRole)
	router.POST(mapAPIPath("/roles/:role"), service.addRole)
	router.PUT(mapAPIPath("/roles/:role"), service.modifyRole)
	router.DELETE(mapAPIPath("/roles/:role"), service.removeRole)

	//user groups
	router.GET(mapAPIPath("/user_groups/"), service.queryGroups)
	router.GET(mapAPIPath("/user_groups/:group"), service.getGroup)
	router.POST(mapAPIPath("/user_groups/:group"), service.addGroup)
	router.PUT(mapAPIPath("/user_groups/:group"), service.modifyGroup)
	router.DELETE(mapAPIPath("/user_groups/:group"), service.removeGroup)

	router.GET(mapAPIPath("/user_groups/:group/members/"), service.queryGroupMembers)
	router.POST(mapAPIPath("/user_groups/:group/members/:user"), service.addGroupMember)
	router.DELETE(mapAPIPath("/user_groups/:group/members/:user"), service.removeGroupMember)

	//users
	router.GET(mapAPIPath("/users/"), service.queryUsers)
	router.GET(mapAPIPath("/users/:user"), service.getUser)
	router.POST(mapAPIPath("/users/:user"), service.createUser)
	router.PUT(mapAPIPath("/users/:user"), service.modifyUser)
	router.DELETE(mapAPIPath("/users/:user"), service.deleteUser)

	router.PUT(mapAPIPath("/users/:user/password/"), service.modifyUserPassword)

	router.GET(mapAPIPath("/user_search/*filepath"), service.searchUsers)

	//sessions
	router.GET(mapAPIPath("/sessions/"), service.querySessions)
	router.POST(mapAPIPath("/sessions/"), service.createSession)
	router.PUT(mapAPIPath("/sessions/:session"), service.updateSession)

	//logs
	router.GET(mapAPIPath("/logs/"), service.queryLogs)
	router.POST(mapAPIPath("/logs/"), service.addLog)
	router.DELETE(mapAPIPath("/logs/"), service.removeLog)

	//visibility
	router.GET(mapAPIPath("/resource_visibilities/"), service.getVisibility)
	router.PUT(mapAPIPath("/resource_visibilities/"), service.updateVisibility)

	router.GET(mapAPIPath("/guest_search/*filepath"), service.searchGuests)
	router.GET(mapAPIPath("/media_image_search/*filepath"), service.searchMediaImages)
	router.GET(mapAPIPath("/disk_image_search/*filepath"), service.searchDiskImages)

	//initial system
	router.GET(mapAPIPath("/system/"), service.getSystemStatus)
	router.POST(mapAPIPath("/system/"), service.initialSystemStatus)

	//OCRS
	if service.corsEnable{
		var paths = []string{
			"/instances/:id",
			"/guests/:id",
			"/guests/",
			"/guests/:id/cores",
			"/guests/:id/memory",
			"/guests/:id/system/",
			"/guests/:id/qos/cpu",
			"/guests/:id/qos/disk",
			"/guests/:id/qos/network",
			"/guests/:id/name/",
			"/guests/:id/auth",
			"/guests/:id/disks/resize/:index",
			"/guests/:id/disks/shrink/:index",
			"/compute_zone_status/",
			"/compute_pool_status/",
			"/compute_pool_status/:pool",
			"/compute_cell_status/:pool",
			"/compute_cell_status/:pool/:cell",
			"/instance_status/:pool",
			"/instance_status/:pool/:cell",
			"/compute_pools/",
			"/compute_pools/:pool",
			"/compute_pool_cells/",
			"/compute_pool_cells/:pool",
			"/compute_pool_cells/:pool/:cell",
			"/address_pools/",
			"/address_pools/:pool",
			"/address_pools/:pool/:type/ranges/",
			"/address_pools/:pool/:type/ranges/:start",
			"/storage_pools/",
			"/storage_pools/:pool",
			"/media_images/",
			"/media_images/:id",
			"/media_images/:id/file/",
			"/disk_images/",
			"/disk_images/:id",
			"/disk_images/:id/file/",
			"/instances/:id/media",
			"/instances/:id/snapshots/",
			"/instances/:id/snapshots/:name",
			"/batch/create_guest/",
			"/batch/create_guest/:id",
			"/batch/delete_guest/",
			"/batch/delete_guest/:id",
			"/batch/stop_guest/",
			"/batch/stop_guest/:id",
			"/migrations/",
			"/migrations/:id",
			"/monitor_channels/:id",
			"/monitor_channels/",
			"/roles/",
			"/roles/:role",
			"/user_groups/",
			"/user_groups/:group",
			"/user_groups/:group/members/",
			"/user_groups/:group/members/:user",
			"/users/",
			"/users/:user",
			"/users/:user/password/",
			"/user_search/*filepath",
			"/sessions/",
			"/sessions/:session",
			"/logs/",
			"/resource_visibilities/",
			"/guest_search/*filepath",
			"/media_image_search/*filepath",
			"/disk_image_search/*filepath",
			"/system/",
		}
		for _, path := range paths{
			router.OPTIONS(mapAPIPath(path), service.allowCORSRequest)
		}
	}
}

func mapAPIPath(path string) string{
	return fmt.Sprintf("%s/v%d%s", APIRoot, APIVersion, path)
}

func (service *FrontEndService) processCORSHeaders(w http.ResponseWriter, r *http.Request){
	if !service.corsEnable{
		return
	}
	var origin = r.Header.Get("Origin")
	if 0 != len(origin){
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}

func (service *FrontEndService) allowCORSRequest(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTION, PUT, DELETE, HEAD")
	var allowedHeaders = []string{
		"Accept",
		"Content-Type",
		"Content-Length",
		"Accept-Encoding",
		"X-CSRF-Token",
		"Access-Control-Allow-Origin",
		HeaderNameSession,
		HeaderNameDate,
		HeaderNameScope,
		HeaderNameAuthorization,
	}
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
	w.WriteHeader(http.StatusOK)
}

func (service *FrontEndService) getLoggedSession(w http.ResponseWriter, r *http.Request) (session LoggedSession, err error){
	service.processCORSHeaders(w, r)
	var sessionID = r.Header.Get(HeaderNameSession)
	if 0 == len(sessionID){
		err = errors.New("unauthenticated request")
		return
	}
	var resp = make(chan SessionResult, 1)
	service.sessionManager.GetSession(sessionID, resp)
	var result = <- resp
	if result.Error != nil{
		err = result.Error
		return
	}
	session = result.Session
	return
}

func (service *FrontEndService) redirectToBackend(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	//check session
	var err error
	if _, err = service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	r.Host = service.backendHost
	if err = service.signatureRequest(r); err != nil{
		err = fmt.Errorf("signature api fail: %s", err.Error())
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	service.reverseProxy.ServeHTTP(w, r)
}

func (service *FrontEndService) signatureRequest(r *http.Request) (err error){
	const (
		defaultScope    = "/default"
		signatureMethod = "Nano-HMAC-SHA256"
	)

	var canonicalRequest, stringToSign, signedHeaders, requestScope, signature string
	var signKey []byte
	var now = time.Now()
	var currentDate = now.Format("20060102")
	requestScope = fmt.Sprintf("%s%s/nano_request",
		currentDate, defaultScope)

	r.Header.Set(HeaderNameScope, requestScope)
	r.Header.Set(HeaderNameDate, now.Format(time.RFC3339))
	r.Header.Set(HeaderNameHost, r.Host)
	{
		//canonicalRequest
		var canonicalURI = url.QueryEscape(url.QueryEscape(r.URL.Path))
		var canonicalQueryString string
		if 0 != len(r.URL.Query()){
			var paramNames []string
			for key := range r.URL.Query(){
				paramNames = append(paramNames, key)
			}
			sort.Sort(sort.StringSlice(paramNames))
			var queryParams []string
			for _, name := range paramNames{
				queryParams = append(queryParams,
					fmt.Sprintf("%s=%s", url.QueryEscape(name), url.QueryEscape(r.URL.Query().Get(name))))
			}
			canonicalQueryString = strings.Join(queryParams, "&")
		}else{
			canonicalQueryString = ""
		}
		var canonicalHeaders string
		var headersBuilder strings.Builder
		var lowerHeaders []string
		var hasBody = true
		var payload []byte
		if http.MethodGet == r.Method || http.MethodHead == r.Method || http.MethodOptions == r.Method{
			hasBody = false
		}else if payload, err = ioutil.ReadAll(r.Body); err != nil{
			if err != io.EOF{
				err = fmt.Errorf("read request body fail: %s", err.Error())
				return
			}
			hasBody = false
		}else if 0 == len(payload){
			hasBody = false
		}
		//hash with sha256
		var hash = sha256.New()
		if !hasBody{
			hash.Write([]byte(""))
		}else {
			//clone request payload
			hash.Write(payload)
			r.Body = ioutil.NopCloser(bytes.NewBuffer(payload))
		}
		var hashedPayload = strings.ToLower(hex.EncodeToString(hash.Sum(nil)))


		for _, headerName := range service.sortedSignatureHeaders{
			if !hasBody && HeaderNameContentType == headerName{
				//ignore content type when no body available
				continue
			}
			var headerValue = r.Header.Get(headerName)
			if 0 == len(headerValue){
				err = fmt.Errorf("header '%s' required", headerName)
				return
			}
			if _, err = headersBuilder.WriteString(fmt.Sprintf("%s:%s\n",
				strings.ToLower(headerName), strings.Trim(headerValue, " "))); err != nil{
				return
			}
			lowerHeaders = append(lowerHeaders, strings.ToLower(headerName))
		}
		canonicalHeaders = headersBuilder.String()
		signedHeaders = strings.Join(lowerHeaders, ";")

		var canonicalRequestContent = strings.Join([]string{
			canonicalURI,
			canonicalQueryString,
			canonicalHeaders,
			signedHeaders,
			hashedPayload,
		}, "\n")
		hash.Reset()
		hash.Write([]byte(canonicalRequestContent))
		canonicalRequest = hex.EncodeToString(hash.Sum(nil))
		//log.Printf("debug: %d bytes of canonical request %s hashed to %s",
		//	len(canonicalRequestContent), canonicalRequestContent, canonicalRequest)
	}
	{

		stringToSign = strings.Join([]string{
			signatureMethod,
			now.Format(time.RFC3339),
			requestScope,
			canonicalRequest,
		}, "\n")
	}
	{
		var builder strings.Builder
		builder.WriteString("nano")
		builder.WriteString(service.apiKey)

		var key = []byte(builder.String())
		var data = []byte(requestScope)
		if signKey, err = computeHMACSha256(key, data); err != nil{
			return
		}
		//log.Printf("debug: content: %s, key %s", stringToSign, hex.EncodeToString(signKey))
		var hmacSignature []byte
		if hmacSignature, err = computeHMACSha256(signKey, []byte(stringToSign)); err != nil{
			return
		}
		signature = hex.EncodeToString(hmacSignature)
	}
	var authorization = fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		signatureMethod, service.apiID, requestScope, signedHeaders, signature)

	r.Header.Set(HeaderNameAuthorization, authorization)
	return nil
}

func computeHMACSha256(key, data []byte) (hash []byte, err error){
	var h = hmac.New(sha256.New, key)
	if _, err = h.Write(data); err != nil{
		return
	}
	hash = h.Sum(nil)
	return
}

func (service *FrontEndService) searchGuests(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	session, err := service.getLoggedSession(w, r)
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	const (
		ParamOwner = "owner"
		ParamGroup = "group"
	)
	var queryParams = r.URL.Query()
	queryParams.Set(ParamOwner, session.User)

	var groupName = session.Group
	{
		var respChan = make(chan UserResult, 1)
		service.userManager.GetVisibility(groupName, respChan)
		var result = <- respChan
		if result.Error != nil{
			err = result.Error
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
		var visibility = result.Visibility
		//replace params
		if visibility.InstanceVisible{
			queryParams.Set(ParamGroup, groupName)
		}
		r.URL.RawQuery = queryParams.Encode()
	}
	r.Host = service.backendHost
	if err = service.signatureRequest(r); err != nil{
		err = fmt.Errorf("signature api fail: %s", err.Error())
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}

	service.reverseProxy.ServeHTTP(w, r)
}

func (service *FrontEndService) searchDiskImages(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	session, err := service.getLoggedSession(w, r)
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	const (
		ParamOwner = "owner"
		ParamGroup = "group"
	)
	var queryParams = r.URL.Query()
	queryParams.Set(ParamOwner, session.User)

	var groupName = session.Group
	{
		var respChan = make(chan UserResult, 1)
		service.userManager.GetVisibility(groupName, respChan)
		var result = <- respChan
		if result.Error != nil{
			err = result.Error
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
		var visibility = result.Visibility
		//replace params
		if visibility.DiskImageVisible{
			queryParams.Set(ParamGroup, groupName)
		}
		r.URL.RawQuery = queryParams.Encode()
	}
	r.Host = service.backendHost
	if err = service.signatureRequest(r); err != nil{
		err = fmt.Errorf("signature api fail: %s", err.Error())
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	service.reverseProxy.ServeHTTP(w, r)
}


func (service *FrontEndService) searchMediaImages(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	session, err := service.getLoggedSession(w, r)
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	const (
		ParamOwner = "owner"
		ParamGroup = "group"
	)
	var queryParams = r.URL.Query()
	queryParams.Set(ParamOwner, session.User)

	var groupName = session.Group
	{
		var respChan = make(chan UserResult, 1)
		service.userManager.GetVisibility(groupName, respChan)
		var result = <- respChan
		if result.Error != nil{
			err = result.Error
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
		var visibility = result.Visibility
		//replace params
		if visibility.MediaImageVisible{
			queryParams.Set(ParamGroup, groupName)
		}
		r.URL.RawQuery = queryParams.Encode()
	}
	r.Host = service.backendHost
	if err = service.signatureRequest(r); err != nil{
		err = fmt.Errorf("signature api fail: %s", err.Error())
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	service.reverseProxy.ServeHTTP(w, r)
}

func (service *FrontEndService) mapSingleFile(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	var filename = path.Base(r.RequestURI)
	var target = filepath.Join(service.webRoot, filename)
	//log.Printf("<frontend> debug: mapped %s => %s", r.RequestURI, target)
	http.ServeFile(w, r, target)
}

func (service *FrontEndService) routeToDefaultPage(w http.ResponseWriter, r *http.Request){
	//log.Printf("<frontend> debug: route %s => %s", r.RequestURI, service.spaPage)
	http.ServeFile(w, r, service.spaPage)
}

type Response struct {
	ErrorCode int         `json:"error_code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
}

const (
	DefaultServerError = 500
)

func ResponseFail(code int, message string, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(Response{code, message, ""})
}

func ResponseOK(data interface{}, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(Response{0, "", data})
}

//user roles

func (service *FrontEndService) queryRoles(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var data = make([]string, 0)
	var respChan = make(chan UserResult, 1)
	service.userManager.QueryRoles(respChan)
	var result = <- respChan
	if result.Error != nil{
		var err = result.Error
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	for _, role := range result.RoleList{
		data = append(data, role.Name)
	}
	ResponseOK(data, w)
}

func (service *FrontEndService) getRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var roleName = params.ByName("role")
	var respChan = make(chan UserResult, 1)
	service.userManager.GetRole(roleName, respChan)
	var result = <- respChan
	if result.Error != nil{
		ResponseFail(DefaultServerError, result.Error.Error(), w)
		return
	}
	type ResponsePayload struct {
		Menu []string `json:"menu,omitempty"`
	}
	var payload = ResponsePayload{Menu:result.Role.Menu}
	ResponseOK(payload, w)
}

func (service *FrontEndService) addRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var roleName = params.ByName("role")
	type RequestData struct {
		Menu []string `json:"menu,omitempty"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.userManager.AddRole(roleName, requestData.Menu, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) modifyRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var roleName = params.ByName("role")
	type RequestData struct {
		Menu []string `json:"menu,omitempty"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.userManager.ModifyRole(roleName, requestData.Menu, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) removeRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var roleName = params.ByName("role")
	var respChan = make(chan error, 1)
	service.userManager.RemoveRole(roleName, respChan)
	var err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}


//user groups

func (service *FrontEndService) queryGroups(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	type RespGroup struct {
		Name    string `json:"name"`
		Display string `json:"display"`
		Member  int    `json:"member"`
	}
	var payload = make([]RespGroup, 0)
	var respChan = make(chan UserResult, 1)
	service.userManager.QueryGroups(respChan)
	var result = <- respChan
	if result.Error != nil{
		var err = result.Error
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	for _, group := range result.GroupList{
		var memberCount = len(group.Members)
		payload = append(payload, RespGroup{group.Name, group.Display, memberCount})
	}
	ResponseOK(payload, w)
}

func (service *FrontEndService) getGroup(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = params.ByName("group")
	var respChan = make(chan UserResult, 1)
	service.userManager.GetGroup(groupName, respChan)
	var result = <- respChan
	if result.Error != nil{
		ResponseFail(DefaultServerError, result.Error.Error(), w)
		return
	}
	type RespGroup struct {
		Name    string   `json:"name"`
		Display string   `json:"display"`
		Role    []string `json:"role,omitempty"`
		Member  []string `json:"member,omitempty"`
	}
	var group = result.Group
	var payload = RespGroup{Name: group.Name, Display: group.Display}
	var members, roles []string
	for memberName, _ := range group.Members{
		members = append(members, memberName)
	}
	for roleName, _ := range group.Roles{
		roles = append(roles, roleName)
	}
	sort.Stable(sort.StringSlice(members))
	sort.Stable(sort.StringSlice(roles))
	payload.Role = roles
	payload.Member = members
	ResponseOK(payload, w)
}

func (service *FrontEndService) addGroup(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = params.ByName("group")
	type RequestData struct {
		Display string   `json:"display"`
		Role    []string `json:"role,omitempty"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.userManager.AddGroup(groupName, requestData.Display, requestData.Role, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) modifyGroup(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = params.ByName("group")
	type RequestData struct {
		Display string   `json:"display"`
		Role    []string `json:"role,omitempty"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.userManager.ModifyGroup(groupName, requestData.Display, requestData.Role, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) removeGroup(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = params.ByName("group")
	var respChan = make(chan error, 1)
	service.userManager.RemoveGroup(groupName, respChan)
	var err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) queryGroupMembers(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = params.ByName("group")
	var respChan = make(chan UserResult, 1)
	service.userManager.QueryGroupMembers(groupName, respChan)
	var result = <- respChan
	if result.Error != nil{
		ResponseFail(DefaultServerError, result.Error.Error(), w)
		return
	}
	var payload = make([]string, 0)
	for _, member := range result.UserList{
		payload = append(payload, member.Name)
	}
	ResponseOK(payload, w)
}

func (service *FrontEndService) addGroupMember(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = params.ByName("group")
	var userName = params.ByName("user")
	var respChan = make(chan error, 1)
	service.userManager.AddGroupMember(groupName, userName, respChan)
	var err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) removeGroupMember(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = params.ByName("group")
	var userName = params.ByName("user")
	var respChan = make(chan error, 1)
	service.userManager.RemoveGroupMember(groupName, userName, respChan)
	var err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}


//users

func (service *FrontEndService) queryUsers(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var payload = make([]string, 0)
	var respChan = make(chan UserResult, 1)
	service.userManager.QueryUsers(respChan)
	var result = <- respChan
	if result.Error != nil{
		var err = result.Error
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	for _, user := range result.UserList{
		payload = append(payload, user.Name)
	}
	ResponseOK(payload, w)
}

func (service *FrontEndService) getUser(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var userName = params.ByName("user")
	var respChan = make(chan UserResult, 1)
	service.userManager.GetUser(userName, respChan)
	var result = <- respChan
	if result.Error != nil{
		ResponseFail(DefaultServerError, result.Error.Error(), w)
		return
	}
	type RespUser struct {
		Name           string `json:"name"`
		Nick           string `json:"nick,omitempty"`
		Mail           string `json:"mail,omitempty"`
	}
	var user = result.User
	var payload = RespUser{Name: user.Name, Nick: user.Nick, Mail:user.Mail}
	ResponseOK(payload, w)
}

func (service *FrontEndService) createUser(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var userName = params.ByName("user")
	type RequestData struct {
		Nick     string `json:"nick,omitempty"`
		Mail     string `json:"mail,omitempty"`
		Password string `json:"password"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.userManager.CreateUser(userName, requestData.Nick, requestData.Mail, requestData.Password, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) modifyUser(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var userName = params.ByName("user")
	type RequestData struct {
		Nick           string `json:"nick,omitempty"`
		Mail           string `json:"mail,omitempty"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.userManager.ModifyUser(userName, requestData.Nick, requestData.Mail, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) deleteUser(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var userName = params.ByName("user")
	var respChan = make(chan error, 1)
	service.userManager.DeleteUser(userName, respChan)
	var err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) modifyUserPassword(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var userName = params.ByName("user")
	type RequestData struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.userManager.ModifyUserPassword(userName, requestData.Old, requestData.New, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) searchUsers(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var query = r.URL.Query()
	var targetGroup = query.Get("group")
	var payload = make([]string, 0)
	var respChan = make(chan UserResult, 1)
	service.userManager.SearchUsers(targetGroup, respChan)
	var result = <- respChan
	if result.Error != nil{
		var err = result.Error
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	for _, user := range result.UserList{
		payload = append(payload, user.Name)
	}
	ResponseOK(payload, w)
}

//sessions

func (service *FrontEndService) querySessions(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var payload = make([]string, 0)
	var respChan = make(chan SessionResult, 1)
	service.sessionManager.QuerySessions(respChan)
	var result = <- respChan
	if result.Error != nil{
		var err = result.Error
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	for _, session := range result.SessionList{
		payload = append(payload, session.ID)
	}
	ResponseOK(payload, w)
}

//func (service *FrontEndService) getSession(w http.ResponseWriter, r *http.Request, params httprouter.Params){
//	session, err := service.getLoggedSession(w, r)
//	if err != nil{
//		ResponseFail(DefaultServerError, err.Error(), w)
//		return
//	}
//	type RespSession struct {
//		User    string   `json:"user"`
//		Menu    []string `json:"menu,omitempty"`
//		Timeout int      `json:"timeout"`
//		Group   string   `json:"group"`
//		Address string   `json:"address,omitempty"`
//	}
//	var payload = RespSession{session.User, session.Menu, session.Timeout, session.Group, session.Address}
//	ResponseOK(payload, w)
//}

func getRemoteIP(r *http.Request) (ip string, err error) {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) -1 ; i >= 0; i-- {
			ip = strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			if realIP := net.ParseIP(ip); realIP != nil{
				return ip, nil
			}
		}
	}
	//get from remote address
	ip, _, err = net.SplitHostPort(r.RemoteAddr)
	if err != nil{
		return
	}
	if net.ParseIP(ip) != nil{
		return ip, nil
	}
	return "", errors.New("no remote address available")
}

func (service *FrontEndService) createSession(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	service.processCORSHeaders(w, r)
	type RequestData struct {
		User     string `json:"user"`
		Password string `json:"password"`
		Nonce    string `json:"nonce"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var remoteAddress string
	remoteAddress, err = getRemoteIP(r)
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	{
		//verify
		var respChan = make(chan error, 1)
		service.userManager.VerifyUserPassword(requestData.User, requestData.Password, respChan)
		err = <- respChan
		if err != nil{
			{
				var respChan = make(chan error, 1)
				//record login fail
				var log = fmt.Sprintf("warning: failed login from %s", remoteAddress)
				service.logManager.AddLog(log, respChan)
				<- respChan
			}
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
	}

	var user LoginUser
	{
		var respChan = make(chan UserResult, 1)
		service.userManager.GetUser(requestData.User, respChan)
		var result = <- respChan
		if result.Error != nil{
			ResponseFail(DefaultServerError, result.Error.Error(), w)
			return
		}
		user = result.User
	}
	{

		//allocate
		var respChan = make(chan SessionResult, 1)
		service.sessionManager.AllocateSession(user.Name, user.Group, requestData.Nonce, remoteAddress,  user.Menu, respChan)
		var result = <- respChan
		if result.Error != nil{
			ResponseFail(DefaultServerError, result.Error.Error(), w)
			return
		}
		type RespSession struct {
			Session string   `json:"session"`
			Group   string   `json:"group"`
			Timeout int      `json:"timeout"`
			Menu    []string `json:"menu"`
			Address string   `json:"address,omitempty"`
		}
		var session = result.Session
		var payload = RespSession{session.ID, session.Group, session.Timeout, session.Menu, session.Address}
		ResponseOK(payload, w)
	}
}

func (service *FrontEndService) updateSession(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var sessionID = params.ByName("session")
	var respChan = make(chan error, 1)
	service.sessionManager.UpdateSession(sessionID, respChan)
	var err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

//logs
func (service *FrontEndService) queryLogs(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	type RequestData struct {
		Limit  int
		Start  int
		After  string
		Before string
	}
	var requestData RequestData

	requestData.After = r.URL.Query().Get("after")
	requestData.Before = r.URL.Query().Get("before")
	var err error

	var limitString = r.URL.Query().Get("limit")
	if "" != limitString{
		requestData.Limit, err = strconv.Atoi(limitString)
		if err != nil{
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
	}

	var startString = r.URL.Query().Get("start")
	if "" != startString{
		requestData.Start, err = strconv.Atoi(startString)
		if err != nil{
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
	}
	const (
		MaxLimit         = 100
		DefaultLimit     = 20
		TimeFormatLayout = "2006-01-02 15:04:05"
		DefaultDuration  = -24 * time.Hour
	)

	var now = time.Now()
	var currentLocation = now.Location()

	var condition LogQueryCondition
	if requestData.Limit == 0 || requestData.Limit > MaxLimit{
		condition.Limit = DefaultLimit
	}else{
		condition.Limit = requestData.Limit
	}
	condition.Start = requestData.Start
	if "" == requestData.Before{
		condition.EndTime = now
	}else{
		condition.EndTime, err = time.ParseInLocation(TimeFormatLayout, requestData.Before, currentLocation)
		if err != nil{
			err = fmt.Errorf("invalid before time '%s', must in format 'YYYY-MM-DD HH:MI:SS'", requestData.Before)
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
	}
	if "" == requestData.After{
		//latest 24 hour
		condition.BeginTime = condition.EndTime.Add(DefaultDuration)
	}else{
		condition.BeginTime, err = time.ParseInLocation(TimeFormatLayout, requestData.After, currentLocation)
		if err != nil{
			err = fmt.Errorf("invalid after time '%s', must in format 'YYYY-MM-DD HH:MI:SS'", requestData.After)
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
	}
	var respChan = make(chan LogResult, 1)
	service.logManager.QueryLog(condition, respChan)
	var result = <- respChan
	if result.Error != nil{
		err = result.Error
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	type logEntry struct {
		ID      string `json:"id"`
		Time    string `json:"time"`
		Content string `json:"content"`
	}
	type respData struct {
		Logs  []logEntry `json:"logs"`
		Total uint       `json:"total"`
	}
	var data respData

	data.Logs = make([]logEntry, 0)
	for _, entry := range result.Logs{
		var log = logEntry{ID:entry.ID, Content:entry.Content}
		log.Time = entry.Time.Format(TimeFormatLayout)
		data.Logs = append(data.Logs, log)
	}
	data.Total = result.Total

	ResponseOK(data, w)
}

func (service *FrontEndService) addLog(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	type RequestData struct {
		Format  string `json:"format,omitempty"`
		Content string `json:"content"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.logManager.AddLog(requestData.Content, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) removeLog(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if _, err := service.getLoggedSession(w, r); err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	type RequestData struct {
		Entries []string `json:"entries"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var respChan = make(chan error, 1)
	service.logManager.RemoveLog(requestData.Entries, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	ResponseOK("", w)
}

func (service *FrontEndService) updateVisibility(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	session, err := service.getLoggedSession(w, r)
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = session.Group
	{
		//update
		var visibility GroupVisibility
		var decoder = json.NewDecoder(r.Body)
		if err = decoder.Decode(&visibility); err != nil{
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
		var respChan = make(chan error, 1)
		service.userManager.UpdateVisibility(groupName, visibility, respChan)
		err = <- respChan
		if err != nil{
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
	}
	ResponseOK("", w)
}

func (service *FrontEndService) getVisibility(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	session, err := service.getLoggedSession(w, r)
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	var groupName = session.Group
	{
		var respChan = make(chan UserResult, 1)
		service.userManager.GetVisibility(groupName, respChan)
		var result = <- respChan
		if result.Error != nil{
			err = result.Error
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
		type VisibilityPayload struct {
			InstanceVisible   bool `json:"instance_visible"`
			DiskImageVisible  bool `json:"disk_image_visible"`
			MediaImageVisible bool `json:"media_image_visible"`
		}
		var v = result.Visibility
		ResponseOK(VisibilityPayload{v.InstanceVisible, v.DiskImageVisible, v.MediaImageVisible}, w)
	}
}

func (service *FrontEndService) getSystemStatus(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	service.processCORSHeaders(w, r)
	type Payload struct {
		Ready bool `json:"ready"`
	}
	var payload = Payload{Ready: false}
	if !service.userInitialed{
		var respChan = make(chan error, 1)
		service.userManager.IsInitialed(respChan)
		var result = <- respChan
		if nil == result{
			//initialed
			service.userInitialed = true
			payload.Ready = true
			log.Println("<frontend> system initialed")
		}
	}else{
		payload.Ready = true
	}
	ResponseOK(payload, w)
}

func (service *FrontEndService) initialSystemStatus(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	service.processCORSHeaders(w, r)
	if service.userInitialed{
		ResponseFail(DefaultServerError, "system already initialed", w)
		return
	}
	type RequestData struct {
		User     string   `json:"user"`
		Group    string   `json:"group,omitempty"`
		Display  string   `json:"display,omitempty"`
		Role     string   `json:"role,omitempty"`
		Password string   `json:"password"`
		Menu     []string `json:"menu"`
	}
	var requestData RequestData
	var decoder = json.NewDecoder(r.Body)
	var err error
	if err = decoder.Decode(&requestData);err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	if 0 == len(requestData.Menu){
		ResponseFail(DefaultServerError, "require at least one menu item", w)
		return
	}

	const (
		DefaultGroup = "admin"
		DefaultDisplay = "Adminitrators of Nano Portal"
		DefaultRole = "super"
	)
	if 0 == len(requestData.Group){
		requestData.Group = DefaultGroup
		log.Printf("<frontend> set default group to '%s'", requestData.Group)
	}
	if 0 == len(requestData.Display){
		requestData.Display = DefaultDisplay
		log.Printf("<frontend> set default group display to '%s'", requestData.Display)
	}
	if 0 == len(requestData.Role){
		requestData.Role = DefaultRole
		log.Printf("<frontend> set default role to '%s'", requestData.Role)
	}
	var respChan = make(chan error, 1)
	service.userManager.Initial(requestData.User, requestData.Group, requestData.Display, requestData.Role,
		requestData.Password, requestData.Menu, respChan)
	err = <- respChan
	if err != nil{
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}else{
		ResponseOK("", w)
	}
}