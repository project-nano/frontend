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
	CurrentVersion = "0.3.1"
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
	router.GET("/", service.defaultLandingPage)
	//API
	router.GET("/instances/:id", service.redirectToBackend)
	router.POST("/instances/:id", service.redirectToBackend)
	router.DELETE("/instances/:id", service.redirectToBackend)

	router.GET("/guests/:id", service.redirectToBackend)
	router.POST("/guests/", service.redirectToBackend)
	router.DELETE("/guests/:id", service.redirectToBackend)
	router.GET("/guest_search/*filepath", service.redirectToBackend)
	router.PUT("/guest/:id/cores", service.redirectToBackend)
	router.PUT("/guest/:id/memory", service.redirectToBackend)
	router.PUT("/guest/:id/auth", service.redirectToBackend)
	router.GET("/guest/:id/auth", service.redirectToBackend)
	router.PUT("/guest/:id/disks/resize/:index", service.redirectToBackend)
	router.PUT("/guest/:id/disks/shrink/:index", service.redirectToBackend)


	router.GET("/compute_zone_status/", service.redirectToBackend)
	router.GET("/compute_pool_status/", service.redirectToBackend)
	router.GET("/compute_pool_status/:pool", service.redirectToBackend)
	router.GET("/compute_cell_status/:pool", service.redirectToBackend)
	router.GET("/compute_cell_status/:pool/:cell", service.redirectToBackend)
	router.GET("/instance_status/:pool", service.redirectToBackend)
	router.GET("/instance_status/:pool/:cell", service.redirectToBackend)

	router.GET("/compute_pools/", service.redirectToBackend)
	router.GET("/compute_pools/:pool", service.redirectToBackend)
	router.POST("/compute_pools/:pool", service.redirectToBackend)
	router.DELETE("/compute_pools/:pool", service.redirectToBackend)
	router.GET("/compute_pool_cells/", service.redirectToBackend)
	router.GET("/compute_pool_cells/:pool", service.redirectToBackend)
	router.POST("/compute_pool_cells/:pool/:cell", service.redirectToBackend)
	router.DELETE("/compute_pool_cells/:pool/:cell", service.redirectToBackend)


	router.GET("/media_images/", service.redirectToBackend)
	router.POST("/media_images/", service.redirectToBackend)
	router.DELETE("/media_images/:id", service.redirectToBackend)
	router.POST("/media_image_files/:id", service.redirectToBackend)

	router.GET("/disk_image_search/*filepath", service.redirectToBackend)
	router.GET("/disk_images/:id", service.redirectToBackend)
	router.POST("/disk_images/", service.redirectToBackend)
	router.DELETE("/disk_images/:id", service.redirectToBackend)
	router.GET("/disk_image_files/:id", service.redirectToBackend)
	router.POST("/disk_image_files/:id", service.redirectToBackend)

	router.GET("/monitor_channels/:id", service.handleEstablishChannel)
	router.POST("/monitor_channels/", service.handleCreateChannel)

	router.POST("/instances/:id/media", service.redirectToBackend)
	router.DELETE("/instances/:id/media", service.redirectToBackend)

	//snapshots
	router.GET("/instances/:id/snapshots/", service.redirectToBackend)
	router.POST("/instances/:id/snapshots/", service.redirectToBackend)
	router.PUT("/instances/:id/snapshots/", service.redirectToBackend)
	router.GET("/instances/:id/snapshots/:name", service.redirectToBackend)
	router.DELETE("/instances/:id/snapshots/:name", service.redirectToBackend)
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