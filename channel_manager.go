package main

import (
	"github.com/project-nano/framework"
	"log"
	"time"
	"github.com/satori/go.uuid"
	"fmt"
)

type MonitorToken struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ChannelResult struct {
	Error   error
	Address string
	MonitorToken
}

type channelCommand struct {
	Type    int
	Address string
	Secret  string
	Channel string
	Result  chan ChannelResult
}

const (
	ChannelCommandCreate = iota
	ChannelCommandEstablish
)

type MonitorChannel struct {
	Protocol string
	Address  string
	Username string
	Password string
	Expire   time.Time
}

type ChannelManager struct {
	channels map[string]MonitorChannel
	commands chan channelCommand
	runner   *framework.SimpleRunner
}

func CreateChannelManager() (manager *ChannelManager, err error){
	const (
		DefaultQueueSize = 1 << 10
	)
	manager = &ChannelManager{}
	manager.channels = map[string]MonitorChannel{}
	manager.commands = make(chan channelCommand, DefaultQueueSize)
	manager.runner = framework.CreateSimpleRunner(manager.Routine)
	return
}


func (manager *ChannelManager)CreateChannel(address, secret string, respChan chan ChannelResult){
	manager.commands <- channelCommand{Type:ChannelCommandCreate, Address:address, Secret:secret, Result:respChan}
}

func (manager *ChannelManager)EstablishChannel(channel string, respChan chan ChannelResult){
	manager.commands <- channelCommand{Type:ChannelCommandEstablish, Channel:channel, Result:respChan}
}

func (manager *ChannelManager) Start() error{
	return manager.runner.Start()
}

func (manager *ChannelManager) Stop() error{
	return manager.runner.Stop()
}

func (manager *ChannelManager)Routine(c framework.RoutineController){
	log.Println("<channel> started")
	const (
		CheckInterval = 2*time.Second
	)
	var checkTicker = time.NewTicker(CheckInterval)

	for !c.IsStopping(){
		select {
		case <- c.GetNotifyChannel():
			log.Println("<channel> stopping...")
			c.SetStopping()
		case <- checkTicker.C:
			manager.checkChannels()
		case cmd := <- manager.commands:
			manager.handleCommand(cmd)
		}
	}
	c.NotifyExit()
	log.Println("<channel> stopped")
}

func (manager *ChannelManager)checkChannels(){
	if 0 == len(manager.channels){
		return
	}
	var now = time.Now()
	var clearList []string
	for id, channel := range manager.channels{
		if now.After(channel.Expire){
			clearList = append(clearList, id)
		}
	}
	if 0 != len(clearList){
		for _, id := range clearList{
			log.Printf("<channel> channel %s expired", id)
			delete(manager.channels, id)
		}
	}
}

func (manager *ChannelManager)handleCommand(cmd channelCommand) {
	var err error
	switch cmd.Type {
	case ChannelCommandCreate:
		err = manager.handleCreateChannel(cmd.Address, cmd.Secret, cmd.Result)
	case ChannelCommandEstablish:
		err = manager.handleEstablishChannel(cmd.Channel, cmd.Result)
	default:
		log.Printf("<channel> invalid command type %d", cmd.Type)
	}
	if err != nil{
		log.Printf("<channel> handle command type %d fail: %s", cmd.Type, err.Error())
	}
}

func (manager *ChannelManager)handleCreateChannel(address, secret string, respChan chan ChannelResult) error{
	const (
		ChannelTimeout = 15*time.Second
		DefaultProtocol = "vnc"
	)
	newID, err := uuid.NewV4()
	if err != nil{
		log.Printf("<channel> generate channel id fail: %s", err.Error())
		respChan <- ChannelResult{Error:err}
		return err
	}
	var channelID = newID.String()
	if _, exists := manager.channels[channelID];exists{
		err = fmt.Errorf("channel '%s' already exists", channelID)
		respChan <- ChannelResult{Error:err}
		return err
	}
	var expire = time.Now().Add(ChannelTimeout)
	var channel = MonitorChannel{DefaultProtocol, address, "", secret, expire}
	manager.channels[channelID] = channel
	log.Printf("<channel> new channel '%s' created, address '%s', secret '%s'", channelID, address, secret)
	var token = MonitorToken{channelID, channel.Protocol, channel.Username, channel.Password}
	respChan <- ChannelResult{MonitorToken:token}
	return nil
}

func (manager *ChannelManager)handleEstablishChannel(channelID string, respChan chan ChannelResult) error{
	channel, exists := manager.channels[channelID]
	if !exists{
		var err = fmt.Errorf("invalid channel '%s'", channelID)
		log.Printf("<channel> establish channel fail: %s", err.Error())
		respChan <- ChannelResult{Error:err}
		return err
	}
	respChan <- ChannelResult{Address:channel.Address}
	log.Printf("<channel> channel '%s' established", channelID)
	delete(manager.channels, channelID)
	return nil
}
