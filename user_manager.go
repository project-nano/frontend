package main

import (
	"path/filepath"
	"nano/framework"
)

type UserRole struct {
	Name string   `json:"name"`
	Menu []string `json:"menu,omitempty"`
}

type UserGroup struct {
	Name    string
	Display string
	Roles   map[string]bool
	Members map[string]bool
}

type LoginUser struct {
	Name           string   `json:"name"`
	Nick           string   `json:"nick,omitempty"`
	Mail           string   `json:"mail,omitempty"`
	Group          string   `json:"group,omitempty"`
	SaltedPassword string   `json:"salted_password"`
	Menu           []string `json:"-"`
}

type UserResult struct {
	Error     error
	Role      UserRole
	RoleList  []UserRole
	Group     UserGroup
	GroupList []UserGroup
	User      LoginUser
	UserList  []LoginUser
}

type userCommandType int

const (
	cmdQueryRole = iota
	cmdGetRole
	cmdAddRole
	cmdModifyRole
	cmdRemoveRole
	cmdQueryGroup
	cmdGetGroup
	cmdAddGroup
	cmdModifyGroup
	cmdRemoveGroup
	cmdQueryGroupMember
	cmdAddGroupMember
	cmdRemoveGroupMember
	cmdQueryGroupRole
	cmdAddGroupRole
	cmdRemoveGroupRole
	cmdQueryUser
	cmdGetUser
	cmdCreateUser
	cmdModifyUser
	cmdDeleteUser
	cmdModifyUserPassword
	cmdVerifyUserPassword
)

type userCMD struct {
	Type       userCommandType
	Role       string
	Group      string
	User       string
	Menu       []string
	ResultChan chan UserResult
	ErrorChan  chan error
}

type UserManager struct {
	users      map[string]LoginUser
	groups     map[string]UserGroup
	roles      map[string]UserRole
	configFile string
	commands   chan userCMD
	framework.SimpleRunner
}

func CreateUserManager(configPath string)  (manager *UserManager, err error){
	const (
		ConfigName = "users.data"
	)
	manager = &UserManager{}
	manager.configFile = filepath.Join(configPath, ConfigName)
	manager.users = map[string]LoginUser{}
	manager.groups = map[string]UserGroup{}
	manager.roles = map[string]UserRole{}
	manager.Initial(manager)
	if err = manager.loadConfig(); err != nil{
		return
	}
	return manager, nil
}

func (manager *UserManager) Routine(){

}

func (manager *UserManager) loadConfig() (err error){
	panic("not implement")
}

func (manager *UserManager) saveConfig() (err error){
	panic("not implement")
}

func (manager *UserManager) QueryRoles(resp chan UserResult)  {

}

func (manager *UserManager) AddRole(role UserRole, resp chan error)  {

}

func (manager *UserManager) GetRole(name string, resp chan UserResult)  {

}

func (manager *UserManager) ModifyRole(role UserRole, resp chan error)  {

}

func (manager *UserManager) RemoveRole(name string, resp chan error)  {

}

func (manager *UserManager) QueryGroups(resp chan UserResult)  {

}

func (manager *UserManager) AddGroup(name, display string, resp chan error)  {

}

func (manager *UserManager) GetGroup(name string, resp chan UserResult)  {

}

func (manager *UserManager) ModifyGroup(name, display string, resp chan error)  {

}

func (manager *UserManager) RemoveGroup(name string, resp chan error)  {

}

func (manager *UserManager) QueryGroupMembers(group string,resp chan UserResult)  {

}

func (manager *UserManager) AddGroupMember(group, user string, resp chan error)  {

}

func (manager *UserManager) RemoveGroupMember(group, user string, resp chan error)  {

}

func (manager *UserManager) QueryGroupRoles(group string,resp chan UserResult)  {

}

func (manager *UserManager) AddGroupRole(group, role string, resp chan error)  {

}

func (manager *UserManager) RemoveGroupRole(group, role string, resp chan error)  {

}

func (manager *UserManager) QueryUsers(resp chan UserResult)  {

}


func (manager *UserManager) GetUser(name string, resp chan UserResult)  {

}

func (manager *UserManager) CreateUser(name, nick, mail, password string, resp chan error)  {

}

func (manager *UserManager) ModifyUser(name, nick, mail string, resp chan error)  {

}

func (manager *UserManager) DeleteUser(name string, resp chan error)  {

}

func (manager *UserManager) ModifyUserPassword(name, old, new string, resp chan error)  {

}

func (manager *UserManager) VerifyUserPassword(name, password string, resp chan error)  {

}