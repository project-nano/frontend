# Change Log

## [0.9.1] - 2019-05-14

### Added

- Get media image

- Query/Add/Remove operate log

- Add version and online manual link to footer

- Add new API "GET /media_image_search/" for filtering media images by owner and group

### Changed

- Default landing page change to 'login.html'

- Add group info in session

- Bind resources to current user/group: Create instance/upload&build images

- Media images filtered using the current user and group

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
