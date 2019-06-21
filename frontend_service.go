package main

import (
	"nano/framework"
	"net"
	"net/http"
	"context"
	"log"
	"net/http/httputil"
	"github.com/julienschmidt/httprouter"
	"fmt"
	"net/url"
	"io"
	"encoding/json"
	"path/filepath"
	"io/ioutil"
	"sort"
	"time"
	"strconv"
	"strings"
	"github.com/pkg/errors"
)

type FrontEndService struct {
	serviceListener net.Listener
	frontendServer  http.Server
	listenAddress   string
	backendHost     string
	backendURL      string
	reverseProxy    *httputil.ReverseProxy
	channelManager  *ChannelManager
	sessionManager  *SessionManager
	userManager     *UserManager
	logManager      *LogManager
	userInitialed   bool
	fileHandler     http.Handler
	runner          *framework.SimpleRunner
}

type Proxy struct {
	service *FrontEndService
}

const (
	CurrentVersion = "1.0.0"
)


func (proxy *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request){
	proxy.service.handleFileRequest(w, r)
}

func CreateFrontEnd(configPath, resourcePath, dataPath string) (service *FrontEndService, err error ) {
	var configFile = filepath.Join(configPath, ConfigFileName)
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return
	}
	var config FrontEndConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return
	}

	service = &FrontEndService{}
	service.listenAddress = fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort)
	service.serviceListener, err = net.Listen("tcp", service.listenAddress)
	if err != nil{
		return
	}
	service.backendHost = config.ServiceHost
	service.backendURL = fmt.Sprintf("http://%s:%d", config.ServiceHost, config.ServicePort)
	proxyUrl, err := url.Parse(service.backendURL)
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
	const (
		CSSPath = "css"
		JSPath = "js"
	)
	router.ServeFiles("/css/*filepath", http.Dir(filepath.Join(resourcePath, CSSPath)))
	router.ServeFiles("/js/*filepath", http.Dir(filepath.Join(resourcePath, JSPath)))

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
	service.fileHandler = http.FileServer(http.Dir(resourcePath))
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
		GET    = iota
		POST
		PUT
		DELETE
	)

	var redirect = func(r *httprouter.Router, path string, method int) {
		switch method {
		case GET:
			r.GET(path, service.redirectToBackend)
		case POST:
			r.POST(path, service.redirectToBackend)
		case PUT:
			r.PUT(path, service.redirectToBackend)
		case DELETE:
			r.DELETE(path, service.redirectToBackend)
		default:
			log.Printf("<frontend> define redirect fail, invalid method %d", method)
		}
	}

	router.GET("/", service.defaultLandingPage)
	router.GET("/initial.html", service.initialSystem)
	router.GET("/monitor_channels/:id", service.handleEstablishChannel)
	router.POST("/monitor_channels/", service.handleCreateChannel)

	//API
	redirect(router, "/instances/:id", GET)
	redirect(router, "/instances/:id", POST)
	redirect(router, "/instances/:id", DELETE)

	redirect(router, "/guests/:id", GET)
	redirect(router, "/guests/", POST)
	redirect(router, "/guests/:id", DELETE)

	redirect(router, "/guest_search/*filepath", GET)
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

	redirect(router, "/media_image_search/*filepath", GET)
	redirect(router, "/media_images/", GET)
	redirect(router, "/media_images/", POST)
	redirect(router, "/media_images/:id", GET)
	redirect(router, "/media_images/:id", DELETE)
	redirect(router, "/media_images/:id", PUT)//modify media image info
	redirect(router, "/media_image_files/:id", POST)

	redirect(router, "/disk_image_search/*filepath", GET)
	redirect(router, "/disk_images/", POST)
	redirect(router, "/disk_images/:id", GET)
	redirect(router, "/disk_images/:id", DELETE)
	redirect(router, "/disk_images/:id", PUT) //modify disk image info
	redirect(router, "/disk_image_files/:id", GET)
	redirect(router, "/disk_image_files/:id", POST)

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

	//migrations
	redirect(router, "/migrations/", GET)
	redirect(router, "/migrations/:id", GET)
	redirect(router, "/migrations/", POST)

	//inner function

	//user roles
	router.GET("/roles/", service.queryRoles)
	router.GET("/roles/:role", service.getRole)
	router.POST("/roles/:role", service.addRole)
	router.PUT("/roles/:role", service.modifyRole)
	router.DELETE("/roles/:role", service.removeRole)

	//user groups
	router.GET("/user_groups/", service.queryGroups)
	router.GET("/user_groups/:group", service.getGroup)
	router.POST("/user_groups/:group", service.addGroup)
	router.PUT("/user_groups/:group", service.modifyGroup)
	router.DELETE("/user_groups/:group", service.removeGroup)

	router.GET("/user_groups/:group/members/", service.queryGroupMembers)
	router.POST("/user_groups/:group/members/:user", service.addGroupMember)
	router.DELETE("/user_groups/:group/members/:user", service.removeGroupMember)

	//users
	router.GET("/users/", service.queryUsers)
	router.GET("/users/:user", service.getUser)
	router.POST("/users/:user", service.createUser)
	router.PUT("/users/:user", service.modifyUser)
	router.DELETE("/users/:user", service.deleteUser)

	router.PUT("/users/:user/password/", service.modifyUserPassword)

	router.GET("/user_search/*filepath", service.searchUsers)

	//sessions
	router.GET("/sessions/", service.querySessions)
	router.GET("/sessions/:session", service.getSession)
	router.POST("/sessions/", service.createSession)
	router.PUT("/sessions/:session", service.updateSession)

	//logs
	router.GET("/logs/", service.queryLogs)
	router.POST("/logs/", service.addLog)
	router.DELETE("/logs/", service.removeLog)
}

func (service *FrontEndService) defaultLandingPage(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	const(
		DefaultURL = "/login.html"
	)
	http.Redirect(w, r, DefaultURL, http.StatusMovedPermanently)
}

func (service *FrontEndService) redirectToBackend(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	r.Host = service.backendHost
	service.reverseProxy.ServeHTTP(w, r)
}

func (service *FrontEndService) handleFileRequest(w http.ResponseWriter, r *http.Request){
	if !service.userInitialed{
		//need initial
		var resp = make(chan error, 1)
		service.userManager.IsInitialed(resp)
		var err = <- resp
		if err != nil{
			//not initialed
			const initialPage = "initial.html"
			log.Printf("<frontend> redirect to initial page '%s'", initialPage)
			http.Redirect(w, r, initialPage, http.StatusTemporaryRedirect)
			return
		}else{
			log.Println("<frontend> system initialed")
			service.userInitialed = true
		}
	}
	service.fileHandler.ServeHTTP(w, r)
}

func (service *FrontEndService) initialSystem(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	if !service.userInitialed{
		service.fileHandler.ServeHTTP(w, r)
		return
	}
	const loginPage = "/login.html"
	log.Printf("<frontend> redirect initial request to login page: %s", loginPage)
	http.Redirect(w, r, loginPage, http.StatusTemporaryRedirect)
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
	return encoder.Encode(Response{code, message, struct{}{}})
}

func ResponseOK(data interface{}, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(Response{0, "", data})
}

//user roles

func (service *FrontEndService) queryRoles(w http.ResponseWriter, r *http.Request, params httprouter.Params){
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

func (service *FrontEndService) getSession(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	var sessionID = params.ByName("session")
	var respChan = make(chan SessionResult, 1)
	service.sessionManager.GetSession(sessionID, respChan)
	var result = <- respChan
	if result.Error != nil{
		ResponseFail(DefaultServerError, result.Error.Error(), w)
		return
	}
	type RespSession struct {
		User    string   `json:"user"`
		Menu    []string `json:"menu,omitempty"`
		Timeout int      `json:"timeout"`
		Group   string   `json:"group"`
		Address string   `json:"address,omitempty"`
	}
	var session = result.Session
	var payload = RespSession{session.User, session.Menu, session.Timeout, session.Group, session.Address}
	ResponseOK(payload, w)
}

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
	{
		//verify
		var respChan = make(chan error, 1)
		service.userManager.VerifyUserPassword(requestData.User, requestData.Password, respChan)
		err = <- respChan
		if err != nil{
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
		var remoteAddress string
		remoteAddress, err = getRemoteIP(r)
		if err != nil{
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
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
