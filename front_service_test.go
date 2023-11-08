package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const (
	testPath = "test"
)

func clearTestEnvironment() (err error) {
	if _, err = os.Stat(testPath); !os.IsNotExist(err) {
		//exists
		err = os.RemoveAll(testPath)
		return
	}
	return nil
}

func getFrontEndServiceForTest() (service *FrontEndService, err error) {
	const (
		DefaultPathPerm = 0740
		DefaultFilePerm = 0640
		webHost         = "192.168.1.167"
		webPort         = 5870
		serviceHost     = webHost
		servicePort     = 5850
		apiKey          = "123456"
		apiID           = "123456"
		webRoot         = "web_root"
	)
	if err = clearTestEnvironment(); err != nil {
		return
	}
	var configPath = filepath.Join(testPath, ConfigPathName)
	if err = os.MkdirAll(configPath, DefaultPathPerm); err != nil {
		return
	}
	//default configure
	var config = FrontEndConfig{
		MaxCores:      DefaultMaxCores,
		MaxMemory:     DefaultMaxMemory,
		MaxDisk:       DefaultMaxDisk,
		ListenAddress: webHost,
		ListenPort:    webPort,
		ServiceHost:   serviceHost,
		ServicePort:   servicePort,
		WebRoot:       webRoot,
		APIKey:        apiKey,
		APIID:         apiID,
	}
	var configFilename = filepath.Join(configPath, ConfigFileName)
	var configFile *os.File
	//create config
	if configFile, err = os.Create(configFilename); err != nil {
		return
	}
	defer func() {
		_ = configFile.Close()
	}()
	var encoder = json.NewEncoder(configFile)
	encoder.SetIndent("", " ")
	if err = encoder.Encode(config); err != nil {
		return
	}
	var dataPath = filepath.Join(testPath, DataPathName)
	//create service
	service, err = CreateFrontEnd(configPath, dataPath)
	return
}

func TestFrontEndService_StartAndStop(t *testing.T) {
	service, err := getFrontEndServiceForTest()
	if err != nil {
		t.Fatalf("load service fail: %s", err.Error())
		return
	}
	if err = service.Start(); err != nil {
		t.Fatalf("start service fail: %s", err.Error())
		return
	}
	if err = service.Stop(); err != nil {
		t.Fatalf("stop service fail: %s", err.Error())
	}
	t.Log("test frontend service start and stop success")
}
