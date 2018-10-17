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
	frontendServer http.Server
	listenAddress  string
	backendHost    string
	backendURL     string
	reverseProxy   *httputil.ReverseProxy
	channelManager *ChannelManager
	framework.SimpleRunner
}

const (
	CurrentVersion = "0.5.1"
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