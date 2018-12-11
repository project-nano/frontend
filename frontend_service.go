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
	framework.SimpleRunner
}

const (
	CurrentVersion = "0.7.1"
)

func CreateFrontEnd(listenHost string, listenPort int, backendHost string, backendPort int) (service *FrontEndService, err error ) {
	service = &FrontEndService{}
	service.listenAddress = fmt.Sprintf("%s:%d", listenHost, listenPort)
	service.serviceListener, err = net.Listen("tcp", service.listenAddress)
	if err != nil{
		return
	}
	service.backendHost = backendHost
	service.backendURL = fmt.Sprintf("http://%s:%d", backendHost, backendPort)
	proxyUrl, err := url.Parse(service.backendURL)
	if err != nil{
		return
	}
	service.reverseProxy = httputil.NewSingleHostReverseProxy(proxyUrl)
	service.channelManager, _ = CreateChannelManager()
	var router = httprouter.New()
	service.registerHandler(router)
	router.ServeFiles("/css/*filepath", http.Dir("resource/css"))
	router.ServeFiles("/js/*filepath", http.Dir("resource/js"))
	router.NotFound = http.FileServer(http.Dir("resource"))

	service.frontendServer.Handler = router
	service.Initial(service)
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

func (service *FrontEndService)Routine(){
	log.Printf("<frontend> %s started", CurrentVersion)
	go service.frontendServer.Serve(service.serviceListener)
	service.channelManager.Start()
	for !service.IsStopping(){
		select {
		case <- service.GetNotifyChannel():
			log.Println("<frontend> stopping server...")
			service.channelManager.Stop()
			service.SetStopping()
			//shutdown server
			ctx, _ := context.WithCancel(context.TODO())
			if err := service.frontendServer.Shutdown(ctx);err != nil{
				log.Printf("<frontsend> shutdown server fail: %s", err.Error())
			}else{
				log.Println("<frontend> server shutdown")
			}

		}
	}
	service.NotifyExit()
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
	redirect(router, "/guest/:id/cores", PUT)
	redirect(router, "/guest/:id/memory", PUT)
	redirect(router, "/guest/:id/auth", PUT)
	redirect(router, "/guest/:id/auth", GET)
	redirect(router, "/guest/:id/disks/resize/:index", PUT)
	redirect(router, "/guest/:id/disks/shrink/:index", PUT)

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
	redirect(router, "/media_images/:id", DELETE)
	redirect(router, "/media_image_files/:id", POST)

	redirect(router, "/disk_image_search/*filepath", GET)
	redirect(router, "/disk_images/:id", GET)
	redirect(router, "/disk_images/", POST)
	redirect(router, "/disk_images/:id", DELETE)
	redirect(router, "/disk_image_files/:id", GET)
	redirect(router, "/disk_image_files/:id", POST)

	redirect(router, "/instances/:id/media", POST)
	redirect(router, "/instances/:id/media", DELETE)

	redirect(router, "/instances/:id/snapshots/", GET)
	redirect(router, "/instances/:id/snapshots/", POST)
	redirect(router, "/instances/:id/snapshots/", PUT)
	redirect(router, "/instances/:id/snapshots/:name", GET)
	redirect(router, "/instances/:id/snapshots/:name", DELETE)

	//migrations
	redirect(router, "/migrations/", GET)
	redirect(router, "/migrations/:id", GET)
	redirect(router, "/migrations/", POST)
	
	//inner function
	
	//user roles
	router.GET("/roles/", service.queryRoles)
	router.POST("/roles/:name", service.addRole)
	router.PUT("/roles/:name", service.modifyRole)
	router.DELETE("/roles/:name", service.removeRole)

	//user groups
	router.GET("/user_groups/", service.queryGroups)
	router.POST("/user_groups/:group", service.addGroup)
	router.PUT("/user_groups/:group", service.modifyGroup)
	router.DELETE("/user_groups/:group", service.removeGroup)

	router.GET("/user_groups/:group/members/", service.queryGroupMembers)
	router.POST("/user_groups/:group/members/:user", service.addGroupMember)
	router.DELETE("/user_groups:group/members/:user", service.removeGroupMember)

	router.GET("/user_groups/:group/roles/", service.queryGroupRoles)
	router.POST("/user_groups/:group/roles/:role", service.addGroupRole)
	router.DELETE("/user_groups:group/roles/:role", service.removeGroupRole)

	//users
	router.GET("/users/", service.queryUsers)
	router.GET("/users/:user", service.getUser)
	router.POST("/users/:user", service.createUser)
	router.PUT("/users/:user", service.modifyUser)
	router.DELETE("/users/:user", service.deleteUser)

	router.PUT("/users/:user/password/", service.modifyUserPassword)
	
	//sessions
	router.GET("/sessions/", service.querySessions)
	router.GET("/sessions/:session", service.getSession)
	router.POST("/sessions/:session", service.createSession)
	router.PUT("/sessions/:session", service.updateSession)
	
	//logs
	router.GET("/logs/", service.queryLogs)
	router.POST("/logs/", service.addLog)
}

func (service *FrontEndService)defaultLandingPage(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	const(
		DefaultURL = "/dashboard.html"
	)
	http.Redirect(w, r, DefaultURL, http.StatusMovedPermanently)
}

func (service *FrontEndService)redirectToBackend(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	r.Host = service.backendHost
	service.reverseProxy.ServeHTTP(w, r)
}


type Response struct {
	ErrorCode int         `json:"error_code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
}

const (
	ResponseDefaultError = 500
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
	
}

func (service *FrontEndService) addRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) modifyRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) removeRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}


//user groups

func (service *FrontEndService) queryGroups(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) addGroup(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) modifyGroup(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) removeGroup(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) queryGroupMembers(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) addGroupMember(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) removeGroupMember(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) queryGroupRoles(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) addGroupRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) removeGroupRole(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

//users

func (service *FrontEndService) queryUsers(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) getUser(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) createUser(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) modifyUser(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) deleteUser(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) modifyUserPassword(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

//sessions

func (service *FrontEndService) querySessions(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) getSession(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) createSession(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) updateSession(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

//logs
func (service *FrontEndService) queryLogs(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}

func (service *FrontEndService) addLog(w http.ResponseWriter, r *http.Request, params httprouter.Params){

}