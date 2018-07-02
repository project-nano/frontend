package main

import (
	"fmt"
	"errors"
	"os"
	"encoding/json"
	"path/filepath"
	"io/ioutil"
	"nano/framework"
)

type FrontEndConfig struct {
	ListenAddress string `json:"address"`
	ListenPort    int    `json:"port"`
	ServiceHost   string `json:"service_host"`
	ServicePort   int    `json:"service_port"`
}

type MainService struct {
	frontend *FrontEndService
}

const (
	ExecuteName     = "frontend"
	ConfigFileName  = "frontend.cfg"
	ConfigPathName  = "config"
)

func (service *MainService)Start() (output string, err error){
	if nil == service.frontend {
		err = errors.New("invalid service")
		return
	}
	if err = service.frontend.Start();err != nil{
		return
	}
	output = fmt.Sprintf("\nlisten at '%s', forward to '%s'\n", service.frontend.GetListenAddress(), service.frontend.GetBackendURL())
	return
}

func (service *MainService)Stop() (output string, err error){
	if nil == service.frontend {
		err = errors.New("invalid service")
		return
	}
	err = service.frontend.Stop()
	return
}

func generateConfigure(workingPath string) (err error){
	const (
		DefaultPathPerm = 0740
	)
	var configPath = filepath.Join(workingPath, ConfigPathName)
	if _, err = os.Stat(configPath); os.IsNotExist(err) {
		//create path
		err = os.Mkdir(configPath, DefaultPathPerm)
		if err != nil {
			return
		}
		fmt.Printf("config path %s created\n", configPath)
	}

	var configFile = filepath.Join(configPath, ConfigFileName)
	if _, err = os.Stat(configFile); os.IsNotExist(err) {
		fmt.Println("No configures available, following instructions to generate a new one.")
		const (
			DefaultConfigPerm = 0640
			DefaultBackEndPort = 5850
			DefaultFrontEndPort = 5870
		)
		var config = FrontEndConfig{}
		if config.ListenAddress, err = framework.ChooseIPV4Address("Portal listen address");err !=nil{
			return
		}
		if config.ListenPort, err = framework.InputInteger("Portal listen port", DefaultFrontEndPort); err !=nil{
			return
		}
		if config.ServiceHost, err = framework.InputString("Backend service address", config.ListenAddress); err !=nil{
			return
		}
		if config.ServicePort, err = framework.InputInteger("Backend service port", DefaultBackEndPort); err != nil{
			return
		}
		//write
		data, err := json.MarshalIndent(config, "", " ")
		if err != nil {
			return err
		}
		if err = ioutil.WriteFile(configFile, data, DefaultConfigPerm); err != nil {
			return err
		}
		fmt.Printf("default configure '%s' generated\n", configFile)
	}
	return
}

func createDaemon(workingPath string) (service framework.DaemonizedService, err error){
	var configPath = filepath.Join(workingPath, ConfigPathName)
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
	var s = MainService{}
	s.frontend, err = CreateFrontEnd(config.ListenAddress, config.ListenPort, config.ServiceHost, config.ServicePort)
	return &s, err
}

func main() {
	framework.ProcessDaemon(ExecuteName, generateConfigure, createDaemon)
}
