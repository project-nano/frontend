# Change Log

## [0.4.1] - 2018-9-29

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
