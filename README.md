# README

## Overview

The FrontEnd is the web portal for users of Nano. It hosts HTML5 web pages based on the REST API of the Core module and also provides authentication and user management for the web portal.

You can modify pages in the path "resource" to meet your need, or even write a whole new module using REST API to replace this one.

Binary release found [here](<https://github.com/project-nano/releases/releases>)

See more detail for [Quick Guide](<https://nanocloud.readthedocs.io/projects/guide/en/latest/concept.html>)

Official Site: <https://nanos.cloud/en-us/>

REST API: <https://nanoen.docs.apiary.io/>

## Build



```go
#git clone https://github.com/project-nano/frontend.git
#cd frontend
#go build -o frontend -ldflags="-w -s"
```



## Command Line

All Nano modules provide the command-line interface, and called like :

< module name > [start | stop | status | halt]

- start: start module service, output error message when start failed, or version information.
- stop: stops the service gracefully. Releases allocated resources and notify any related modules.
- status: checks if the module is running.
- halt: terminate service immediately.

You can call the FrontEnd module both in the absolute path and relative path.

```
#cd /opt/nano/frontend
#./frontend start

or

#/opt/nano/frontend/frontend start
```

Please check the log file "log/frontend.log" when encountering errors.

## Configure

Configuration stores in file 'config/frontend.cfg'.

| Parameter        | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| **address**      | Listening address of web portal, IPv4 format like '192.168.100'. |
| **port**         | Listening port of web portal, 5870 in default as integer.    |
| **service_host** | Listening address of backend service(the Core module), IPv4 format like '192.168.100'. |
| **service_port** | Listening port of backend service(the Core module), 5850 in default as integer. |



