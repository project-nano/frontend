package main

import (
	"net/http"
	"github.com/julienschmidt/httprouter"
	"encoding/json"
	"log"
	"fmt"
	"github.com/pkg/errors"
	"github.com/gorilla/websocket"
	"net"
)

func (service *FrontEndService)handleCreateChannel(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	type userRequest struct {
		Guest string `json:"guest"`
	}
	var request userRequest
	var decoder = json.NewDecoder(r.Body)
	if err := decoder.Decode(&request);err != nil{
		log.Printf("<%s> [create channel] parse request fail: %s", r.RemoteAddr, err.Error())
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	{
		log.Printf("<%s> [create channel] recv request for guest '%s'", r.RemoteAddr, request.Guest)
		type NetworkConfig struct {
			DisplayAddress string `json:"display_address"`
		}
		type MonitorConfig struct {
			MonitorSecret string        `json:"monitor_secret"`
			Internal      NetworkConfig `json:"internal"`
		}
		type userResponse struct {
			ErrorCode int           `json:"error_code"`
			Message   string        `json:"message"`
			Data      MonitorConfig `json:"data"`
		}
		resp, err := http.Get(fmt.Sprintf("%s/guests/%s", service.backendURL, request.Guest))
		if err != nil{
			log.Printf("<%s> [create channel] get guest config fail: %s", r.RemoteAddr, err.Error())
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
		defer resp.Body.Close()
		var result userResponse
		decoder = json.NewDecoder(resp.Body)
		if err = decoder.Decode(&result);err != nil{
			log.Printf("<%s> [create channel] parse guest config fail: %s", r.RemoteAddr, err.Error())
			ResponseFail(DefaultServerError, err.Error(), w)
			return
		}
		if 0 != result.ErrorCode{
			log.Printf("<%s> [create channel] get guest config fail: %s", r.RemoteAddr, result.Message)
			ResponseFail(DefaultServerError, result.Message, w)
			return
		}
		var respChan = make(chan ChannelResult)
		service.channelManager.CreateChannel(result.Data.Internal.DisplayAddress, result.Data.MonitorSecret, respChan)
		var tokenResult = <- respChan
		if tokenResult.Error != nil{
			log.Printf("<%s> [create channel] create channel fail: %s", r.RemoteAddr, tokenResult.Error.Error())
			ResponseFail(DefaultServerError, tokenResult.Error.Error(), w)
			return
		}
		log.Printf("<%s> [create channel] channel '%s' created", r.RemoteAddr, tokenResult.ID)
		ResponseOK(tokenResult.MonitorToken, w)
	}
}

func (service *FrontEndService)handleEstablishChannel(w http.ResponseWriter, r *http.Request, params httprouter.Params){
	var channelID = params.ByName("id")
	if "" == channelID{
		err := errors.New("must specify channel id")
		log.Printf("<%s> [establish channel] parse request fail: %s", r.RemoteAddr, err.Error())
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	log.Printf("<%s> [establish channel] channel '%s'", r.RemoteAddr, channelID)
	var respChan = make(chan ChannelResult)
	service.channelManager.EstablishChannel(channelID, respChan)
	var result = <- respChan
	if result.Error != nil{
		log.Printf("<%s> [establish channel] get channel fail: %s", r.RemoteAddr, result.Error.Error())
		ResponseFail(DefaultServerError, result.Error.Error(), w)
		return
	}
	var targetAddress = result.Address
	const (
		DefaultSubProtocol = "binary"
		VncProtocol = "tcp"
	)
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		Subprotocols: []string{DefaultSubProtocol},
	}
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil{
		log.Printf("<%s> [establish channel] upgrade fail: %s", r.RemoteAddr, err.Error())
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	defer wsConn.Close()
	vncConn, err := net.Dial(VncProtocol, targetAddress)
	if err != nil{
		log.Printf("<%s> [establish channel] open vnc channel fail: %s", r.RemoteAddr, err.Error())
		ResponseFail(DefaultServerError, err.Error(), w)
		return
	}
	defer vncConn.Close()
	go forwardWebSocketToVnc(wsConn, vncConn, r.RemoteAddr)
	var buffer = make([]byte, 4 << 10)
	var n int
	for{
		n, err = vncConn.Read(buffer)
		if err != nil{
			log.Printf("<%s> [establish channel] recv from vnc fail: %s", r.RemoteAddr, err.Error())
			break
		}
		if err = wsConn.WriteMessage(websocket.BinaryMessage, buffer[:n]); err != nil{
			log.Printf("<%s> [establish channel] send to websocket fail: %s", r.RemoteAddr, err.Error())
			break
		}
	}
	log.Printf("<%s> [establish channel] closed", r.RemoteAddr)
}

func forwardWebSocketToVnc(wsConn *websocket.Conn, vncConn net.Conn, address string)  {
	for{
		msgType, data, err := wsConn.ReadMessage()
		if err != nil{
			log.Printf("<%s> [establish channel] recv from websocket fail: %s", address, err.Error())
			break
		}
		if msgType != websocket.BinaryMessage{
			log.Printf("<%s> [establish channel] ignore message type %d from websocket", address, msgType)
			continue
		}
		if _, err = vncConn.Write(data);err != nil{
			log.Printf("<%s> [establish channel] write to vnc fail: %s", address, err.Error())
			break
		}
	}
	log.Printf("<%s> [establish channel] forward finished", address)
}