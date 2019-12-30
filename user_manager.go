package main

import (
	"path/filepath"
	"github.com/project-nano/framework"
	"log"
	"sort"
	"fmt"
	"github.com/pkg/errors"
	"crypto/rand"
	"golang.org/x/crypto/bcrypt"
	"os"
	"encoding/json"
	"io/ioutil"
	"encoding/base64"
	"regexp"
)

type UserRole struct {
	Name string   `json:"name"`
	Menu []string `json:"menu,omitempty"`
}

type GroupVisibility struct {
	InstanceVisible   bool `json:"instance_visible,omitempty"`
	DiskImageVisible  bool `json:"disk_image_visible,omitempty"`
	MediaImageVisible bool `json:"media_image_visible,omitempty"`
}

type UserGroup struct {
	Name       string          `json:"name"`
	Display    string          `json:"display,omitempty"`
	Roles      map[string]bool `json:"-"`
	Members    map[string]bool `json:"-"`
	Visibility GroupVisibility `json:"visibility"`
}

type LoginUser struct {
	Name   string          `json:"name"`
	Nick   string          `json:"nick,omitempty"`
	Mail   string          `json:"mail,omitempty"`
	Group  string          `json:"group,omitempty"`
	Secret EncryptedSecret `json:"secret"`
	Menu   []string        `json:"-"`
}

type UserResult struct {
	Error      error
	Role       UserRole
	RoleList   []UserRole
	Group      UserGroup
	GroupList  []UserGroup
	User       LoginUser
	UserList   []LoginUser
	Visibility GroupVisibility
}

type cryptMethod int

const (
	methodBCrypt = iota
)

type EncryptedSecret struct {
	Method cryptMethod `json:"method"`
	Salt   string      `json:"salt"`
	Hash   string      `json:"hash"`
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
	cmdQueryUser
	cmdGetUser
	cmdCreateUser
	cmdModifyUser
	cmdDeleteUser
	cmdModifyUserPassword
	cmdVerifyUserPassword
	cmdSearchUser
	cmdIsInitialed
	cmdUpdateVisibility
	cmdGetVisibility
	cmdInitial
)

type userCMD struct {
	Type       userCommandType
	Role       string
	Group      string
	User       string
	Display    string
	Nick       string
	Mail       string
	Challenge  string
	Password   string
	Menu       []string
	RoleList   []string
	Visibility GroupVisibility
	ResultChan chan UserResult
	ErrorChan  chan error
}

type UserManager struct {
	users      map[string]LoginUser
	groups     map[string]UserGroup
	roles      map[string]UserRole
	configFile string
	nameRegex  *regexp.Regexp
	commands   chan userCMD
	runner     *framework.SimpleRunner
}

var ObscuredSecretError = errors.New("invalid user or password")

func CreateUserManager(configPath string)  (manager *UserManager, err error){
	const (
		ConfigName = "users.data"
		NameRegexp = "[^\\da-zA-Z-_.]"
	)
	manager = &UserManager{}
	manager.configFile = filepath.Join(configPath, ConfigName)
	manager.commands = make(chan userCMD, 1 << 10)
	manager.users = map[string]LoginUser{}
	manager.groups = map[string]UserGroup{}
	manager.roles = map[string]UserRole{}
	manager.nameRegex, err = regexp.Compile(NameRegexp)
	if err != nil{
		return
	}
	manager.runner = framework.CreateSimpleRunner(manager.Routine)
	if err = manager.loadConfig(); err != nil{
		return
	}
	return manager, nil
}
func (manager *UserManager) Start() error{
	return manager.runner.Start()
}

func (manager *UserManager) Stop() error{
	return manager.runner.Stop()
}

func (manager *UserManager) Routine(c framework.RoutineController){
	log.Println("<user> started")
	for !c.IsStopping(){
		select {
		case <- c.GetNotifyChannel():
			c.SetStopping()
		case cmd := <-manager.commands:
			manager.handleCommand(cmd)
		}
	}
	c.NotifyExit()
	log.Println("<user> stopped")
}

type GroupConfig struct {
	Name       string          `json:"name"`
	Display    string          `json:"display,omitempty"`
	Role       []string        `json:"role,omitempty"`
	Members    []string        `json:"members,omitempty"`
	Visibility GroupVisibility `json:"visibility,omitempty"`
}

type UserConfig struct {
	Roles  []UserRole    `json:"roles,omitempty"`
	Groups []GroupConfig `json:"groups,omitempty"`
	Users  []LoginUser   `json:"users,omitempty"`
}

func (manager *UserManager) IsUserAvailable() bool{
	return  0 != len(manager.users)
}

func (manager *UserManager) loadConfig() (err error){
	if _, err = os.Stat(manager.configFile);os.IsNotExist(err){
		log.Printf("<user> user data '%s' not available", manager.configFile)
		return nil
	}
	file, err := os.Open(manager.configFile)
	if err != nil{
		return
	}
	defer file.Close()
	var decoder = json.NewDecoder(file)
	var config UserConfig
	if err = decoder.Decode(&config); err != nil{
		return
	}
	for _, role := range config.Roles{
		manager.roles[role.Name] = role
	}
	for _, user := range config.Users{
		manager.users[user.Name] = user
	}
	for _, groupConfig := range config.Groups{
		var group = UserGroup{Name:groupConfig.Name, Display:groupConfig.Display, Visibility: groupConfig.Visibility}
		group.Roles = map[string]bool{}
		group.Members = map[string]bool{}
		for _, roleName := range groupConfig.Role{
			group.Roles[roleName] = true
		}
		for _, memberName := range groupConfig.Members{
			if user, exists := manager.users[memberName]; !exists{
				err = fmt.Errorf("invalid member '%s' in group '%s'", memberName, group.Name)
				return
			}else{
				user.Group = group.Name
				manager.users[memberName] = user
			}

			group.Members[memberName] = true
		}
		manager.groups[group.Name] = group
	}
	log.Printf("<user> %d role(s), %d group(s), %d user(s) loaded from '%s'",
		len(manager.roles), len(manager.groups), len(manager.users), manager.configFile)
	return nil
}

func (manager *UserManager) saveConfig() (err error){
	const (
		DefaultFilePerm = 0640
	)
	var config UserConfig
	for _, user := range manager.users{
		config.Users = append(config.Users, user)
	}
	for _, role := range manager.roles{
		config.Roles = append(config.Roles, role)
	}
	for _, group := range manager.groups{
		var groupConfig = GroupConfig{Name:group.Name, Display:group.Display, Visibility:group.Visibility}
		for roleName, _ := range group.Roles{
			groupConfig.Role = append(groupConfig.Role, roleName)
		}
		for memberName, _ := range group.Members{
			groupConfig.Members = append(groupConfig.Members, memberName)
		}
		config.Groups = append(config.Groups, groupConfig)
	}
	data, err := json.MarshalIndent(config, "", " ")
	if err != nil{
		return
	}
	if err = ioutil.WriteFile(manager.configFile, data, DefaultFilePerm); err != nil{
		return
	}
	log.Printf("<user> %d role(s), %d group(s), %d user(s) saved to '%s'",
		len(config.Roles), len(config.Groups), len(config.Users), manager.configFile)
	return nil
}

func (manager *UserManager) QueryRoles(resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdQueryRole, ResultChan:resp}
}

func (manager *UserManager) AddRole(name string, menu []string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdAddRole, Role:name, Menu:menu, ErrorChan:resp}
}

func (manager *UserManager) GetRole(name string, resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdGetRole, Role:name, ResultChan:resp}
}

func (manager *UserManager) ModifyRole(name string, menu []string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdModifyRole, Role:name, Menu:menu, ErrorChan:resp}
}

func (manager *UserManager) RemoveRole(name string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdRemoveRole, Role:name, ErrorChan:resp}
}

func (manager *UserManager) QueryGroups(resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdQueryGroup, ResultChan:resp}
}

func (manager *UserManager) AddGroup(name, display string, roleList []string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdAddGroup, Group:name, Display:display, RoleList:roleList, ErrorChan:resp}
}

func (manager *UserManager) GetGroup(name string, resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdGetGroup, Group:name, ResultChan:resp}
}

func (manager *UserManager) ModifyGroup(name, display string, roleList []string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdModifyGroup, Group:name, Display:display, RoleList:roleList, ErrorChan:resp}
}

func (manager *UserManager) RemoveGroup(name string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdRemoveGroup, Group:name, ErrorChan:resp}
}

func (manager *UserManager) QueryGroupMembers(group string,resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdQueryGroupMember, Group:group, ResultChan:resp}
}

func (manager *UserManager) AddGroupMember(group, user string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdAddGroupMember, Group:group, User:user, ErrorChan:resp}
}

func (manager *UserManager) RemoveGroupMember(group, user string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdRemoveGroupMember, Group:group, User:user, ErrorChan:resp}
}

func (manager *UserManager) QueryUsers(resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdQueryUser, ResultChan:resp}
}

func (manager *UserManager) GetUser(name string, resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdGetUser, User:name, ResultChan:resp}
}

func (manager *UserManager) CreateUser(name, nick, mail, password string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdCreateUser, User:name, Nick: nick, Mail:mail, Password:password, ErrorChan:resp}
}

func (manager *UserManager) ModifyUser(name, nick, mail string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdModifyUser, User:name, Nick: nick, Mail:mail, ErrorChan:resp}
}

func (manager *UserManager) DeleteUser(name string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdDeleteUser, User:name, ErrorChan:resp}
}

func (manager *UserManager) ModifyUserPassword(name, old, new string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdModifyUserPassword, User:name, Challenge:old, Password:new, ErrorChan:resp}
}

func (manager *UserManager) VerifyUserPassword(name, password string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdVerifyUserPassword, User:name, Challenge:password, ErrorChan:resp}
}

func (manager *UserManager) SearchUsers(groupName string, resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdSearchUser, Group:groupName, ResultChan:resp}
}

func (manager *UserManager) IsInitialed(resp chan error)  {
	manager.commands <- userCMD{Type: cmdIsInitialed, ErrorChan:resp}
}

func (manager *UserManager) UpdateVisibility(group string, visibility GroupVisibility, resp chan error)  {
	manager.commands <- userCMD{Type: cmdUpdateVisibility, Group:group, Visibility:visibility, ErrorChan:resp}
}

func (manager *UserManager) GetVisibility(group string, resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdGetVisibility, Group:group, ResultChan:resp}
}

func (manager *UserManager) Initial(user, group, display, role, password string, menuList []string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdInitial, User: user, Group: group, Display: display, Role: role, Password: password, Menu: menuList, ErrorChan: resp}
}

func (manager *UserManager) handleCommand(cmd userCMD){
	var err error
	switch cmd.Type {
	case cmdQueryRole:
		err = manager.handleQueryRoles(cmd.ResultChan)
	case cmdGetRole:
		err = manager.handleGetRole(cmd.Role, cmd.ResultChan)
	case cmdAddRole:
		err = manager.handleAddRole(cmd.Role, cmd.Menu, cmd.ErrorChan)
	case cmdModifyRole:
		err = manager.handleModifyRole(cmd.Role, cmd.Menu, cmd.ErrorChan)
	case cmdRemoveRole:
		err = manager.handleRemoveRole(cmd.Role, cmd.ErrorChan)
	case cmdQueryGroup:
		err = manager.handleQueryGroups(cmd.ResultChan)
	case cmdGetGroup:
		err = manager.handleGetGroup(cmd.Group, cmd.ResultChan)
	case cmdAddGroup:
		err = manager.handleAddGroup(cmd.Group, cmd.Display, cmd.RoleList, cmd.ErrorChan)
	case cmdModifyGroup:
		err = manager.handleModifyGroup(cmd.Group, cmd.Display, cmd.RoleList, cmd.ErrorChan)
	case cmdRemoveGroup:
		err = manager.handleRemoveGroup(cmd.Group, cmd.ErrorChan)
	case cmdQueryGroupMember:
		err = manager.handleQueryGroupMembers(cmd.Group, cmd.ResultChan)
	case cmdAddGroupMember:
		err = manager.handleAddGroupMember(cmd.Group, cmd.User, cmd.ErrorChan)
	case cmdRemoveGroupMember:
		err = manager.handleRemoveGroupMember(cmd.Group, cmd.User, cmd.ErrorChan)
	case cmdQueryUser:
		err = manager.handleQueryUsers(cmd.ResultChan)
	case cmdGetUser:
		err = manager.handleGetUser(cmd.User, cmd.ResultChan)
	case cmdCreateUser:
		err = manager.handleCreateUser(cmd.User, cmd.Nick, cmd.Mail, cmd.Password, cmd.ErrorChan)
	case cmdModifyUser:
		err = manager.handleModifyUser(cmd.User, cmd.Nick, cmd.Mail, cmd.ErrorChan)
	case cmdDeleteUser:
		err = manager.handleDeleteUser(cmd.User, cmd.ErrorChan)
	case cmdModifyUserPassword:
		err = manager.handleModifyUserPassword(cmd.User, cmd.Challenge, cmd.Password, cmd.ErrorChan)
	case cmdVerifyUserPassword:
		err = manager.handleVerifyUserPassword(cmd.User, cmd.Challenge, cmd.ErrorChan)
	case cmdSearchUser:
		err = manager.handleSearchUsers(cmd.Group, cmd.ResultChan)
	case cmdIsInitialed:
		err = manager.handleIsInitialed(cmd.ErrorChan)
	case cmdUpdateVisibility:
		err = manager.handleUpdateVisibility(cmd.Group, cmd.Visibility, cmd.ErrorChan)
	case cmdGetVisibility:
		err = manager.handleGetVisibility(cmd.Group, cmd.ResultChan)
	case cmdInitial:
		err = manager.handleInitial(cmd.User, cmd.Group, cmd.Display, cmd.Role, cmd.Password, cmd.Menu, cmd.ErrorChan)
	default:
		log.Printf("<user> unsupport command type %d", cmd.Type)
		return 
	}
	if err != nil{
		log.Printf("<user> handle command type %d fail: %s", cmd.Type, err.Error())
	}
	
}

func (manager *UserManager) handleQueryRoles(resp chan UserResult) (err error){
	var names []string
	for roleName, _ := range manager.roles{
		names = append(names, roleName)
	}
	sort.Stable(sort.StringSlice(names))
	var result = make([]UserRole, 0)
	for _, roleName := range names{
		role, exists := manager.roles[roleName]
		if !exists{
			err = fmt.Errorf("invalid role %s", roleName)
			resp <- UserResult{Error:err}
			return err
		}
		result = append(result, role)
	}
	resp <- UserResult{RoleList:result}
	return nil
}

func (manager *UserManager) handleAddRole(name string, menu []string, resp chan error) (err error){
	if err = manager.validateName(name); err != nil{
		resp <- err
		return
	}
	if _, exists := manager.roles[name]; exists{
		err = fmt.Errorf("role '%s' already exists", name)
		resp <- err
		return err		
	}
	var role = UserRole{name, menu}
	manager.roles[name] = role
	log.Printf("<user> role '%s' added with %d menu item(s)", name, len(menu))
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleGetRole(name string, resp chan UserResult)  (err error){
	role, exists := manager.roles[name]
	if !exists{
		err = fmt.Errorf("invalid role '%s'", name)
		resp <- UserResult{Error:err}
		return err
	}
	resp <- UserResult{Role:role}
	return nil
}

func (manager *UserManager) handleModifyRole(name string, menu []string, resp chan error) (err error){
	role, exists := manager.roles[name]
	if !exists{
		err = fmt.Errorf("role '%s' not exists", name)
		resp <- err
		return err
	}
	role.Menu = menu
	manager.roles[name] = role
	log.Printf("<user> role '%s' modified with %d menu item(s)", name, len(menu))
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleRemoveRole(roleName string, resp chan error) (err error){
	if _, exists := manager.roles[roleName]; !exists{
		err = fmt.Errorf("role '%s' not exists", roleName)
		resp <- err
		return err
	}
	for groupName, group := range manager.groups{
		if _, exists := group.Roles[roleName];exists{
			err = fmt.Errorf("role '%s' attached with group '%s'", roleName, groupName)
			resp <- err
			return err
		}
	}
	delete(manager.roles, roleName)
	log.Printf("<user> role '%s' removed", roleName)
	resp <- nil
	return manager.saveConfig()
}


func (manager *UserManager) handleQueryGroups(resp chan UserResult)   (err error){
	var names []string
	for groupName, _ := range manager.groups{
		names = append(names, groupName)
	}
	sort.Stable(sort.StringSlice(names))
	var result = make([]UserGroup, 0)
	for _, groupName := range names{
		group, exists := manager.groups[groupName]
		if !exists{
			err = fmt.Errorf("invalid group %s", groupName)
			resp <- UserResult{Error:err}
			return err
		}
		result = append(result, group)
	}
	resp <- UserResult{GroupList:result}
	return nil
}

func (manager *UserManager) handleAddGroup(name, display string, roleList []string, resp chan error) (err error){
	if err = manager.validateName(name); err != nil{
		resp <- err
		return
	}

	if _, exists := manager.groups[name]; exists{
		err = fmt.Errorf("group '%s' already exists", name)
		resp <- err
		return err
	}
	var group = UserGroup{name, display, map[string]bool{}, map[string]bool{}, GroupVisibility{}}
	for _, roleName := range roleList{
		if _, exists := manager.roles[roleName]; !exists{
			err = fmt.Errorf("invalid role '%s'", roleName)
			resp <- err
			return err
		}
		group.Roles[roleName] = true
	}
	manager.groups[name] = group
	log.Printf("<user> group '%s' added", name)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleGetGroup(name string, resp chan UserResult)  (err error){
	group, exists := manager.groups[name]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", name)
		resp <- UserResult{Error:err}
		return err
	}
	resp <- UserResult{Group:group}
	return nil
}

func (manager *UserManager) handleModifyGroup(name, display string, roleList []string, resp chan error)  (err error){
	group, exists := manager.groups[name];
	if !exists{
		err = fmt.Errorf("group '%s' not exists", name)
		resp <- err
		return err
	}
	group.Display = display
	var roles = map[string]bool{}
	for _, roleName := range roleList{
		if _, exists := manager.roles[roleName]; !exists{
			err = fmt.Errorf("invalid role '%s'", roleName)
			resp <- err
			return err
		}
		roles[roleName] = true
	}
	group.Roles = roles
	manager.groups[name] = group
	log.Printf("<user> group '%s' modified", name)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleRemoveGroup(groupName string, resp chan error) (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("group '%s' not exists", groupName)
		resp <- err
		return err
	}
	for memberName, _ := range group.Members{
		err = fmt.Errorf("member '%s' attached with group '%s'", memberName, groupName)
		resp <- err
		return err
	}
	delete(manager.groups, groupName)
	log.Printf("<user> group '%s' removed", groupName)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleQueryGroupMembers(groupName string,resp chan UserResult) (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", groupName)
		resp <- UserResult{Error:err}
		return err
	}
	var names []string
	for memberName, _ := range group.Members{
		names = append(names, memberName)
	}
	sort.Stable(sort.StringSlice(names))
	var memberList []LoginUser
	for _, memberName := range names{
		member, exists := manager.users[memberName]
		if !exists{
			err = fmt.Errorf("invalid member '%s'", memberName)
			resp <- UserResult{Error:err}
			return err
		}
		memberList = append(memberList, member)
	}
	resp <- UserResult{UserList: memberList}
	return nil
}

func (manager *UserManager) handleAddGroupMember(groupName, userName string, resp chan error) (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", groupName)
		resp <- err
		return err
	}
	if _, exists := group.Members[userName]; exists{
		err = fmt.Errorf("member '%s' already in group '%s'", userName, groupName)
		resp <- err
		return err
	}
	user, exists := manager.users[userName]
	if !exists{
		err = fmt.Errorf("invalid user '%s'", userName)
		resp <- err
		return err
	}
	if "" != user.Group{
		err = fmt.Errorf("user '%s' already joined group '%s'", userName, groupName)
		resp <- err
		return err
	}
	user.Group = groupName
	manager.users[userName] = user
	group.Members[userName] = true
	manager.groups[groupName] = group
	log.Printf("<user> member '%s' added to group '%s'", userName, groupName)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleRemoveGroupMember(groupName, userName string, resp chan error)  (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", groupName)
		resp <- err
		return err
	}
	if _, exists := group.Members[userName]; !exists{
		err = fmt.Errorf("member '%s' not in group '%s'", userName, groupName)
		resp <- err
		return err
	}
	user, exists := manager.users[userName]
	if !exists{
		err = fmt.Errorf("invalid user '%s'", userName)
		resp <- err
		return err
	}
	if user.Group != groupName{
		err = fmt.Errorf("user '%s' not in group '%s'", userName, groupName)
		resp <- err
		return err
	}
	user.Group = ""
	manager.users[userName] = user
	delete(group.Members, userName)
	manager.groups[groupName] = group
	log.Printf("<user> member '%s' removed from group '%s'", userName, groupName)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleQueryUsers(resp chan UserResult)  (err error){
	var names []string
	for userName, _ := range manager.users{
		names = append(names, userName)
	}
	sort.Stable(sort.StringSlice(names))
	var result = make([]LoginUser, 0)
	for _, userName := range names{
		user, exists := manager.users[userName]
		if !exists{
			err = fmt.Errorf("invalid user %s", userName)
			resp <- UserResult{Error:err}
			return err
		}
		result = append(result, user)
	}
	resp <- UserResult{UserList:result}
	return nil
}

func (manager *UserManager) handleGetUser(name string, resp chan UserResult)  (err error){
	user, exists := manager.users[name]
	if !exists{
		err = fmt.Errorf("invalid user '%s'", name)
		resp <- UserResult{Error:err}
		return err
	}
	if "" != user.Group{
		group, exists := manager.groups[user.Group]
		if !exists{
			err = fmt.Errorf("invalid group '%s' for user '%s'", user.Group, name)
			resp <- UserResult{Error:err}
			return err
		}
		var menuMap = map[string]bool{}
		for roleName, _ := range group.Roles{
			role, exists := manager.roles[roleName]
			if !exists{
				err = fmt.Errorf("invalid role '%s' for group '%s'", roleName, user.Group)
				resp <- UserResult{Error:err}
				return err
			}
			for _, menuName := range role.Menu{
				menuMap[menuName] = true
			}
		}
		for menuName, _ := range menuMap{
			user.Menu = append(user.Menu, menuName)
		}
	}
	resp <- UserResult{User:user}
	return nil
}

func (manager *UserManager) handleCreateUser(name, nick, mail, password string, resp chan error)  (err error){
	if err = manager.validateName(name); err != nil{
		resp <- err
		return
	}

	if _, exists := manager.users[name]; exists{
		err = fmt.Errorf("user '%s' already exists", name)
		resp <- err
		return err
	}
	if err = isSecurePassword(password); err != nil{
		resp <- err
		return err
	}
	secret, err := hashPassword(methodBCrypt, password)
	if err != nil{
		resp <- err
		return err
	}
	var user = LoginUser{Name:name, Nick:nick, Mail:mail, Secret:secret}
	manager.users[name] = user
	log.Printf("<user> new user '%s' created", name)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleModifyUser(name, nick, mail string, resp chan error)  (err error){
	user, exists := manager.users[name]
	if !exists{
		err = fmt.Errorf("invalid user '%s'", name)
		resp <- err
		return err
	}
	if "" != mail{
		user.Mail = mail
	}
	if "" != nick{
		user.Nick = nick
	}
	manager.users[name] = user
	log.Printf("<user> user '%s' modified", name)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleDeleteUser(name string, resp chan error)  (err error){
	if _, exists := manager.users[name]; !exists{
		err = fmt.Errorf("invalid user '%s'", name)
		resp <- err
		return err
	}
	delete(manager.users, name)
	log.Printf("<user> user '%s' deleted", name)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleModifyUserPassword(name, old, new string, resp chan error)  (err error){
	user, exists := manager.users[name]
	if !exists{
		err = fmt.Errorf("invalid user '%s'", name)
		resp <- ObscuredSecretError
		return err
	}
	if err = verifyPassword(old, user.Secret); err != nil{
		resp <- ObscuredSecretError
		return err
	}
	if err = isSecurePassword(new); err != nil{
		resp <- err
		return err
	}
	user.Secret, err = hashPassword(methodBCrypt, new)
	if err != nil{
		resp <- err
		return err
	}
	manager.users[name] = user
	log.Printf("<user> password of user '%s' modified", name)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleVerifyUserPassword(name, password string, resp chan error)  (err error){
	user, exists := manager.users[name]
	if !exists{
		err = fmt.Errorf("invalid user '%s'", name)
		resp <- ObscuredSecretError
		return err
	}
	if err = verifyPassword(password, user.Secret); err != nil{
		resp <- ObscuredSecretError
		return err
	}
	resp <- nil
	return nil
}

func (manager *UserManager) handleSearchUsers(groupName string, resp chan UserResult)  (err error){
	var names []string
	for userName, user := range manager.users{
		if user.Group == groupName{
			names = append(names, userName)
		}
	}
	sort.Stable(sort.StringSlice(names))
	var result = make([]LoginUser, 0)
	for _, userName := range names{
		user, exists := manager.users[userName]
		if !exists{
			err = fmt.Errorf("invalid user %s", userName)
			resp <- UserResult{Error:err}
			return err
		}
		result = append(result, user)
	}
	resp <- UserResult{UserList:result}
	return nil
}

func (manager *UserManager) handleIsInitialed(resp chan error)  (err error) {
	if !manager.IsUserAvailable(){
		err = errors.New("system not initial")
		resp <- err
	}else{
		resp <- nil
	}
	return nil
}

func (manager *UserManager) handleUpdateVisibility(groupName string, visibility GroupVisibility, resp chan error) (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", groupName)
		resp <- err
		return
	}
	group.Visibility = visibility
	manager.groups[groupName] = group
	resp <- nil
	log.Printf("<user> resource visibility of group '%s' updated", groupName)
	return manager.saveConfig()
}

func (manager *UserManager) handleGetVisibility(groupName string, resp chan UserResult) (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", groupName)
		resp <- UserResult{Error:err}
		return
	}
	resp <- UserResult{Visibility: group.Visibility}
	return nil
}

func (manager *UserManager) handleInitial(userName, groupName, displayName, roleName, password string, menuList []string, resp chan error) (err error) {
	if 0 != len(manager.users){
		err = errors.New("system already initialed")
		resp <- err
		return
	}
	if err = manager.validateName(userName); err != nil{
		err = fmt.Errorf("invalid user name: %s", err.Error())
		resp <- err
		return
	}
	if err = manager.validateName(groupName); err != nil{
		err = fmt.Errorf("invalid group name: %s", err.Error())
		resp <- err
		return
	}
	if err = manager.validateName(roleName); err != nil{
		err = fmt.Errorf("invalid role name: %s", err.Error())
		resp <- err
		return
	}
	var exists = false
	if _, exists = manager.users[userName]; exists{
		err = fmt.Errorf("user '%s' already exists", userName)
		resp <- err
		return
	}
	if _, exists = manager.roles[roleName]; exists{
		err = fmt.Errorf("role '%s' already exists", roleName)
		resp <- err
		return
	}
	if _, exists = manager.groups[groupName]; exists{
		err = fmt.Errorf("group '%s' already exists", groupName)
		resp <- err
		return
	}
	if err = isSecurePassword(password); err != nil{
		resp <- err
		return
	}
	if 0 == len(menuList){
		errors.New("require at least one menu item")
		resp <- err
		return
	}
	secret, err := hashPassword(methodBCrypt, password)
	if err != nil{
		resp <- err
		return err
	}
	var user = LoginUser{Name:userName, Secret:secret}
	var role = UserRole{roleName, menuList}

	var groupMember = map[string]bool{ userName: true}
	var groupRole = map[string]bool{roleName: true}
	var group = UserGroup{groupName, displayName, groupRole, groupMember, GroupVisibility{}}

	manager.users[userName] = user
	manager.roles[roleName] = role
	manager.groups[groupName] = group
	log.Printf("<user> initialed user '%s.%s' with role '%s', %d menus enabled", groupName, userName, roleName, len(menuList))
	resp <- nil
	return nil
}

func (manager *UserManager) validateName(name string) (err error){
	var matched = manager.nameRegex.FindStringSubmatch(name)
	if 0 != len(matched){
		err = fmt.Errorf("invalid char '%s' in name (only letters/digit/'-'/'_'/'.' allowed)", matched[0])
		return err
	}
	return nil
}

func isSecurePassword(password string) (err error){
	const (
		LeastLength = 8
	)
	if len(password) < LeastLength{
		err = fmt.Errorf("length of password must > %d", LeastLength)
		return
	}
	var lower, upper, digit = false, false, false
	var content = []byte(password)
	for _, char := range content{
		if !digit && (char >= 0x30 && char <= 0x39){
			digit = true
		}
		if !lower && (char >= 0x61 && char <= 0x7A){
			lower = true
		}
		if !upper && (char >= 0x41 && char <= 0x5A){
			upper = true
		}
	}
	if !digit{
		err = errors.New("password must have a digit at least")
		return
	}
	if !lower{
		err = errors.New("password must have a lower letter at least")
		return
	}
	if !upper{
		err = errors.New("password must have a upper letter at least")
		return
	}
	return nil
}

func hashPassword(method cryptMethod, password string) (secret EncryptedSecret, err error){
	const (
		SaltLength = 32
	)
	var randomData = make([]byte, SaltLength)
	_, err = rand.Read(randomData)
	if err != nil{
		return
	}
	var salt = base64.StdEncoding.EncodeToString(randomData)
	secret.Method = method
	secret.Salt = string(salt)
	var input = append([]byte(password), salt...)
	hashed, err := bcrypt.GenerateFromPassword(input, bcrypt.DefaultCost)
	if err != nil{
		return
	}
	secret.Hash = string(hashed)
	return
}

func verifyPassword(password string, secret EncryptedSecret) (err error){
	if methodBCrypt != secret.Method{
		err = fmt.Errorf("invalid crypt method %d", secret.Method)
		return
	}
	var input = append([]byte(password), []byte(secret.Salt)...)
	var hash = []byte(secret.Hash)
	return bcrypt.CompareHashAndPassword(hash, input)
}