# Change Log

## [1.4.0] - 2023-11-07

### 新增

- 配置文件"frontend.cfg"新增选项max_cores用于设置创建云主机的最大核心数，默认值24
- 配置文件"frontend.cfg"新增选项max_memory用于设置创建云主机的最大内存容量(GB)，默认值32
- 配置文件"frontend.cfg"新增选项max_disk用于设置创建云主机的最大磁盘容量(GB)，默认值64

### 变更

- 更新依赖包及go版本
- 新增front_service测试用例
- 接口'GET: /system/'返回资源配额

### Added

- Add option "max_cores" to configure file "frontend.cfg", default value is 24
- Add option "max_memory" in GB to configure file "frontend.cfg", default value is 32
- Add option "max_disk" in GB to configure file "frontend.cfg", default value is 64

### Changed

- update to go 1.20
- update dependent packages
- Add test cases to front_service
- Return max resource limit when get system status on path 'GET: /system/'

### Fixed

- Search guests not filter by owner and group

## [1.3.1] - 2021-02-18

### Added

- Search guests
- Enable/Disable auto start option

## [1.3.0] - 2020-11-08

### Added

- Forward request for sync images/security policy group

### Fixed

- Return an explicit error when login with a user does not belong to any group
- Remove from the group when deleting a user

## [1.2.0] - 2020-04-15

### Added

- Query/Change storage path
- Manage system templates
- Create guest using template
- Reset monitor secret

### Fixed

- Huge memory occupied when uploading images cause OOM kill

## [1.1.3] - 2019-12-29

### Added

- Add web_root option to "frontend.cfg" for hosting portal files
- Add cors_enable option to "frontend.cfg" for CORS control

### Changed

- A new portal completely was rewritten using React
- Web pages move from 'resource' to 'web_root'

### Fixed

- Visibility interface broken
- Query logs missing and wrong order    

## [1.1.2] - 2019-12-13

### Changed

- Enable CORS request to monitor channel

## [1.1.0] - 2019-11-05

### Added 

- Add signature when call Core API
- Add go mod

### Changed

- Call core API via prefix '/api/v1/'
- Change "/media_image_files/:id" to "/media_images/:id/file/"
- Change "/disk_image_files/:id" to "/disk_images/:id/file/"

## [1.0.0] - 2019-07-14

### Added

- Create guests with QoS options

- Modify CPU priority in guest detail

- Set threshold of Disk/Network IO in guest detail

- Batch stop guests

- Enable get/update group visibility

- Record failed login

### Changed

- URL of guest operates change from '/guest/' to '/guests/'.

- Search guest/media/disk images via session

## [0.9.1] - 2019-05-27

### Added

- Get media image

- Query/Add/Remove operate log

- Add version and online manual link to footer

- Add new API "GET /media_image_search/" for filtering media images by owner and group

- Modify disk/media images

- Add operate logs in most pages

### Changed

- Default landing page change to 'login.html'

- Add group info in session

- Bind resources to current user/group: Create instance/upload&build images

- Media images filtered using the current user and group

- Display the appropriate page according to the menu after login

- Add padding space for sidenav

- Move start/stop/restart/reset instance into nano.js

## [0.8.2] - 2019-04-4

### Fixed

- Prompt an invalid dialog when removing ranges from an address pool

- Logout when deleting address pool/computing pool/storage pool

- Prompt an invalid dialog when removing a cell from computing pool

- Logout when deleting a media/disk image

- Logout when modify user/password

- Logout when deleting user

- Logout when removing role/group/group member

## [0.8.1] - 2019-03-21

### Added

- Check resource path

- Enable batch creating and deleting/modify guest name/modify image info

- Batch creating/deleting guest

- Modify user password

- Modify guest name

### Changed

- Locate resource using ABS path

- Adapt to new runnable implement

- Verify guest name before submit creating request

- Navigation menu change to the sidebar

- Update chartjs to v2.8

## [0.7.1] - 2018-12-11

### Added

- Role/Group/User management

- Session management

- Invoke system initial page when no user configured

- Enable reset system

- Add "legacy system" option when create new instance

- Add uptime to dashboard.html

## [0.6.1] - 2018-11-30

### Added

- Redirect address pool/range API

- Address pool/range management page

### Changed

- Address pool option when creating/modifing compute pool

## [0.5.1] - 2018-11-3

### Added

- Multi-language support

- Enable/Disable cell

- Enable failover option in compute pool

- Migrate instance

### Changed

- Optimize console output when starting module

## [0.4.1] - 2018-10-2

### Added

- Support storage pool management

- Modify compute pool

- Get compute cell info

- Standalone google materialize icons

- Mark instance lost status when cell stop/disconnected

- Add image id in list

### Fixed

- No response to click start or insert media button when no media available.

- Auto fresh page become slower after a long time running

- Deleted instance count in the dashboard

- Output message without clear previous info in the list

## [0.3.1] - 2018-8-29

### Added

- Create time of Instance

- Create/modify time of Image

- Snapshot management: create/ delete / revert

- Insert / eject media image

### Changed

- Enable instance funtions in instance monitor page

- Change cpu/memory usage to bar chart in dashboard/instance monitor

- Open new tab for monitor/snapshots/details of instances list

## 2018-8-17

### Added

- Support choose installed module when cloning from an image

- Enable change admin password/ create new admin/ disk auto resize/ data disk mount when Cloud-Init module installed

- Add auto fresh in instances.html

### Modified

- Optimize instances/cells auto refresh, interval reduced to 5 seconds

- Fixed: multiple image names displayed when starting with media

## 2018-8-7

### Modified

- Display instance address/container cell in instances/instance_list

- Display VNC address/secret in detail page

## 2018-8-6

### Modified

- Add auto fresh switch in cell/instance list

## [0.2.1] - 2018-7-31

### Added

- Doc: Modify core/memory/disk size, shrink disk, set/get password

- Forward Request: Modify core/memory/disk size, shrink disk, set/get password

- Add guest modify page: instance_detail.html

## [0.1.2] - 2018-7-25

### Modified

- Version output

- Disk image upload and download

- Add auto refresh to compute_cells.html and instance_list.html
