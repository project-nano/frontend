# Nano FrontEnd

[[版本历史/ChangeLog](CHANGELOG.md)]

[English Version](#introduce)

### 简介

FrontEnd是Nano项目自带的Web管理门户，对集群进行图形化管理。FrontEnd的服务基于[Core模块](https://github.com/project-nano/core)的API接口实现，独立进行账号管理。

由于涉及网络配置，建议使用专用Installer进行部署，项目最新版本请访问[此地址](https://github.com/project-nano/releases)

[项目官网](https://nanos.cloud/)

[项目全部源代码](https://github.com/project-nano)

### 编译

环境要求

- CentOS 7 x86
- Golang 1.20

```
准备依赖的framework
$git clone https://github.com/project-nano/framework.git

准备编译源代码
$git clone https://github.com/project-nano/frontend.git

编译
$cd frontend
$go build
```

编译成功在当前目录生成二进制文件frontend

### 使用

环境要求

- CentOS 7 x86



```
执行以下指令，启动FrontEnd模块
$./frontend start

也可以使用绝对地址调用或者写入开机启动脚本，比如
$/opt/nano/frontend/frontend start

```

模块启动后会输出提供形如http://192.168.5.3:5870的Web访问地址，在浏览器中打开即可。

模块运行日志输入在log/frontend.log文件中，用于查错和调试



页面初次启动，会提示创建超级用户账号，初始化之后就能开始对Nano集群进行管理了。

!!! **请注意：FrontEnd没有密码重置功能或者特殊后门，请牢记管理员密码，遗失后将无法访问系统**!!!

此外，除了模块启动功能，FrontEnd还支持以下参数

| 参数   | 说明                               |
| ------ | ---------------------------------- |
| start  | 启动服务                           |
| stop   | 停止服务                           |
| status | 检查当前服务状态                   |
| halt   | 强行中止服务（用于服务异常时重启） |



### 配置

模块关键配置信息存储在'config/frontend.cfg'

| 配置项           | 值类型 | 默认值                                      | 说明                                                    |
| ---------------- | ------ | ------------------------------------------- | ------------------------------------------------------- |
| **address**      | 字符串 |                                             | 提供管理页面服务的主机地址，IPv4格式                    |
| **port**         | 整数   | 5870                                        | 提供管理页面服务的主机端口，默认5870                    |
| **service_host** | 字符串 |                                             | Core模块API服务的主机地址，需要与Core模块配置一致       |
| **service_port** | 整数   | 5850                                        | Core模块API服务的监听端口，需要与Core模块配置一致       |
| **api_key**      | 字符串 | ‘ThisIsAKeyPlaceHolder_ChangeToYourContent’ | 用于Core模块API服务校验的密文，需要与Core模块配置一致   |
| **api_id**       | 字符串 | ‘dummyID’                                   | 用于Core模块API服务校验的标识ID，需要与Core模块配置一致 |
| **web_root**     | 字符串 | ‘web_root’                                  | Portal项目生成的页面文件存放路径                        |

假设FrontEnd模块地址为192.168.1.167，Core模块地址192.168.1.168，示例配置文件如下

```json
{
 "address": "192.168.1.167",
 "port": 5870,
 "service_host": "192.168.1.168",
 "service_port": 5850,
 "api_key": "ThisIsAKeyPlaceHolder_ChangeToYourContent",
 "api_id": "dummyID",
 "web_root": "web_root"
}
```



### 目录结构

模块主要目录和文件如下

| 目录/文件           | 说明                     |
| ------------------- | ------------------------ |
| frontend            | 模块二进制执行文件       |
| config/frontend.cfg | 模块配置文件             |
| data/log            | 管理页面操作日志存储文件 |
| log/frontend.log    | 模块运行日志             |
| web_root            | 页面文件存放目录         |
| web_root/index.html | 页面入口                 |



### Introduce

FrontEnd is the web portal that comes with the Nano project, managing clusters via GUI. The service is implemented based on the API interfaces of the [Core module](https://github.com/project-nano/core),  with its own accounts system.

It is recommended to use a dedicated Installer for deployment. For the latest project version, please visit [this address](https://github.com/project-nano/releases).

[Official Project Website](https://us.nanos.cloud/en/)

[Full Source Code of the Project](https://github.com/project-nano)

### Compilation

Requirements

- CentOS 7 x86
- Golang 1.20

```
Prepare the dependent framework
$git clone https://github.com/project-nano/framework.git

Prepare the source code for compilation
$git clone https://github.com/project-nano/frontend.git

Compile
$cd frontend
$go build
```

The compiled binary file "frontend" will be generated in the current directory when success.

### Usage

Requirements

- CentOS 7 x86

```
Start module
$./frontend start

Alternatively, you can use an absolute address or write it into a startup script, such as:
$/opt/nano/frontend/frontend start
```

After the module starts, it will provide a web address that can be accessed via browser, such as http://192.168.5.3:5870.

The module logs are output to file: log/frontend.log

**!!! Please note: There is no password recover or backdoor in FrontEnd. Please remember your password carefully, or it will lost forever. !!!** 

FrontEnd also supports the following commands:

| Parameter | Description                                                  |
| --------- | ------------------------------------------------------------ |
| start     | Start the service                                            |
| stop      | Stop the service                                             |
| status    | Check the current service status                             |
| halt      | Forcefully terminate the service (restart when there is an exception) |

### Configuration

The main configuration is stored in file: config/frontend.cfg

| Configuration Item | Value Type | Default Value                               | Description                                                  |
| ------------------ | ---------- | ------------------------------------------- | ------------------------------------------------------------ |
| **address**        | String     |                                             | The host address for the management portal, IPv4 such as '192.168.3.1' |
| **port**           | Integer    | 5870                                        | The host port for the management portal, default is 5870     |
| **service_host**   | String     |                                             | The host address of API service of Core module. Must be the same as the configuration of Core module |
| **service_port**   | Integer    | 5850                                        | The listening port of API service of Core module. Must be the same as the configuration of Core module. default is 5850 |
| **api_key**        | String     | 'ThisIsAKeyPlaceHolder_ChangeToYourContent' | The encryption text used for verifying API service, must be the same as the configuration of Core module. |
| **api_id**         | String     | 'dummyID'                                   | The ID used for verifying API service, Must be the same as the configuration of Core module. |
| **web_root**       | String     | 'web_root'                                  | The path where the page files stored                         |

Assuming that the FrontEnd module address is 192.168.1.167 and the Core module address is 192.168.1.168, an example configuration file is as follows:

```json
{
 "address": "192.168.1.167",
 "port": 5870,
 "service_host": "192.168.1.168",
 "service_port": 5850,
 "api_key": "ThisIsAKeyPlaceHolder_ChangeToYourContent",
 "api_id": "dummyID",
 "web_root": "web_root"
}
```

### Directory Structure

| Directory/File      | Description                         |
| ------------------- | ----------------------------------- |
| frontend            | Binary execution file of the module |
| config/frontend.cfg | Configuration file                  |
| data/log            | Web operation logs                  |
| log/frontend.log    | Module running log                  |
| web_root            | Web page files                      |
| web_root/index.html | Web entry point                     |

