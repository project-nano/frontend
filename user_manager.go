package main

import (
	"path/filepath"
	"nano/framework"
	"log"
	"sort"
	"fmt"
	"github.com/pkg/errors"
	"regexp"
	"crypto/rand"
	"golang.org/x/crypto/bcrypt"
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
	Name   string          `json:"name"`
	Nick   string          `json:"nick,omitempty"`
	Mail   string          `json:"mail,omitempty"`
	Group  string          `json:"-`
	Secret EncryptedSecret `json:"secret"`
	Menu   []string        `json:"-"`
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
	Display    string
	Nick       string
	Mail       string
	Challenge  string
	Password   string
	Menu       []string
	ResultChan chan UserResult
	ErrorChan  chan error
}

type UserManager struct {
	users         map[string]LoginUser
	groups        map[string]UserGroup
	roles         map[string]UserRole
	passwordRegex *regexp.Regexp
	configFile    string
	commands      chan userCMD
	framework.SimpleRunner
}

var ObscuredSecretError = errors.New("invalid user or password")

func CreateUserManager(configPath string)  (manager *UserManager, err error){
	const (
		ConfigName = "users.data"
	)
	manager = &UserManager{}
	manager.configFile = filepath.Join(configPath, ConfigName)
	manager.users = map[string]LoginUser{}
	manager.groups = map[string]UserGroup{}
	manager.roles = map[string]UserRole{}
	const (
		exp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\\$%\\^&\\*])(?=.{8,})"
	)
	manager.passwordRegex, err = regexp.Compile(exp)
	if err != nil{
		return
	}

	manager.Initial(manager)
	if err = manager.loadConfig(); err != nil{
		return
	}
	return manager, nil
}

func (manager *UserManager) Routine(){
	log.Println("<user> started")
	for !manager.IsStopping(){
		select {
		case <- manager.GetNotifyChannel():
			manager.SetStopping()
		case cmd := <-manager.commands:
			manager.handleCommand(cmd)
		}
	}
	manager.NotifyExit()
	log.Println("<user> stopped")
}

func (manager *UserManager) loadConfig() (err error){
	panic("not implement")
}

func (manager *UserManager) saveConfig() (err error){
	panic("not implement")
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

func (manager *UserManager) AddGroup(name, display string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdAddGroup, Group:name, Display:display, ErrorChan:resp}
}

func (manager *UserManager) GetGroup(name string, resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdGetGroup, Group:name, ResultChan:resp}
}

func (manager *UserManager) ModifyGroup(name, display string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdModifyGroup, Group:name, Display:display, ErrorChan:resp}
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

func (manager *UserManager) QueryGroupRoles(group string,resp chan UserResult)  {
	manager.commands <- userCMD{Type: cmdQueryGroupRole, Group:group, ResultChan:resp}
}

func (manager *UserManager) AddGroupRole(group, role string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdAddGroupRole, Group:group, Role:role, ErrorChan:resp}
}

func (manager *UserManager) RemoveGroupRole(group, role string, resp chan error)  {
	manager.commands <- userCMD{Type: cmdRemoveGroupRole, Group:group, Role:role, ErrorChan:resp}
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
		err = manager.handleAddGroup(cmd.Group, cmd.Display, cmd.ErrorChan)
	case cmdModifyGroup:
		err = manager.handleModifyGroup(cmd.Group, cmd.Display, cmd.ErrorChan)
	case cmdRemoveGroup:
		err = manager.handleRemoveGroup(cmd.Group, cmd.ErrorChan)
	case cmdQueryGroupMember:
		err = manager.handleQueryGroupMembers(cmd.Group, cmd.ResultChan)
	case cmdAddGroupMember:
		err = manager.handleAddGroupMember(cmd.Group, cmd.User, cmd.ErrorChan)
	case cmdRemoveGroupMember:
		err = manager.handleRemoveGroupMember(cmd.Group, cmd.User, cmd.ErrorChan)
	case cmdQueryGroupRole:
		err = manager.handleQueryGroupRoles(cmd.Group, cmd.ResultChan)
	case cmdAddGroupRole:
		err = manager.handleAddGroupRole(cmd.Group, cmd.Role, cmd.ErrorChan)
	case cmdRemoveGroupRole:
		err = manager.handleRemoveGroupRole(cmd.Group, cmd.Role, cmd.ErrorChan)
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

func (manager *UserManager) handleRemoveRole(name string, resp chan error) (err error){
	if _, exists := manager.roles[name]; !exists{
		err = fmt.Errorf("role '%s' not exists", name)
		resp <- err
		return err
	}
	delete(manager.roles, name)
	log.Printf("<user> role '%s' removed", name)
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

func (manager *UserManager) handleAddGroup(name, display string, resp chan error) (err error){
	if _, exists := manager.groups[name]; exists{
		err = fmt.Errorf("group '%s' already exists", name)
		resp <- err
		return err
	}
	var group = UserGroup{name, display, map[string]bool{}, map[string]bool{}}
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

func (manager *UserManager) handleModifyGroup(name, display string, resp chan error)  (err error){
	group, exists := manager.groups[name];
	if !exists{
		err = fmt.Errorf("group '%s' not exists", name)
		resp <- err
		return err
	}
	group.Display = display
	manager.groups[name] = group
	log.Printf("<user> group '%s' modified", name)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleRemoveGroup(name string, resp chan error) (err error){
	if _, exists := manager.groups[name]; !exists{
		err = fmt.Errorf("group '%s' not exists", name)
		resp <- err
		return err
	}
	delete(manager.groups, name)
	log.Printf("<user> group '%s' removed", name)
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
	if _, exists = manager.users[userName];!exists{
		err = fmt.Errorf("invalid user '%s'", userName)
		resp <- err
		return err
	}
	group.Members[userName] = true
	manager.groups[groupName] = group
	log.Printf("<user> add member '%s' to group '%s'", userName, groupName)
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
	if _, exists = manager.users[userName];!exists{
		err = fmt.Errorf("invalid user '%s'", userName)
		resp <- err
		return err
	}
	delete(group.Members, userName)
	manager.groups[groupName] = group
	log.Printf("<user> remove member '%s' from group '%s'", userName, groupName)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleQueryGroupRoles(groupName string,resp chan UserResult)  (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", groupName)
		resp <- UserResult{Error:err}
		return err
	}
	var names []string
	for roleName, _ := range group.Roles{
		names = append(names, roleName)
	}
	sort.Stable(sort.StringSlice(names))
	var roleList []UserRole
	for _, roleName := range names{
		role, exists := manager.roles[roleName]
		if !exists{
			err = fmt.Errorf("invalid role '%s'", roleName)
			resp <- UserResult{Error:err}
			return err
		}
		roleList = append(roleList, role)
	}
	resp <- UserResult{RoleList:roleList}
	return nil
}

func (manager *UserManager) handleAddGroupRole(groupName, roleName string, resp chan error)  (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", groupName)
		resp <- err
		return err
	}
	if _, exists := group.Roles[roleName]; exists{
		err = fmt.Errorf("role '%s' already in group '%s'", roleName, groupName)
		resp <- err
		return err
	}
	if _, exists = manager.roles[roleName];!exists{
		err = fmt.Errorf("invalid role '%s'", roleName)
		resp <- err
		return err
	}
	group.Roles[roleName] = true
	manager.groups[groupName] = group
	log.Printf("<user> add role '%s' to group '%s'", roleName, groupName)
	resp <- nil
	return manager.saveConfig()
}

func (manager *UserManager) handleRemoveGroupRole(groupName, roleName string, resp chan error)  (err error){
	group, exists := manager.groups[groupName]
	if !exists{
		err = fmt.Errorf("invalid group '%s'", groupName)
		resp <- err
		return err
	}
	if _, exists := group.Roles[roleName]; !exists{
		err = fmt.Errorf("role '%s' not in group '%s'", roleName, groupName)
		resp <- err
		return err
	}
	if _, exists = manager.roles[roleName];!exists{
		err = fmt.Errorf("invalid role '%s'", roleName)
		resp <- err
		return err
	}
	delete(group.Roles, roleName)
	manager.groups[groupName] = group
	log.Printf("<user> remove role '%s' from group '%s'", roleName, groupName)
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
	resp <- UserResult{User:user}
	return nil
}

func (manager *UserManager) handleCreateUser(name, nick, mail, password string, resp chan error)  (err error){
	if _, exists := manager.users[name]; exists{
		err = fmt.Errorf("user '%s' already exists", name)
		resp <- err
		return err
	}
	if err = isSecurePassword(password, manager.passwordRegex); err != nil{
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
	if err = isSecurePassword(new, manager.passwordRegex); err != nil{
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

func isSecurePassword(password string, checker *regexp.Regexp) (err error){
	const (
		LeastLength = 8
	)
	if len(password) < LeastLength{
		err = fmt.Errorf("length of password must > %d", LeastLength)
		return
	}
	if !checker.MatchString(password){
		err = errors.New("password must contain one lowercase, one uppercase letter, and one digit")
		return
	}
	return nil
}

func hashPassword(method cryptMethod, password string) (secret EncryptedSecret, err error){
	const (
		SaltLength = 32
	)
	var salt = make([]byte, SaltLength)
	_, err = rand.Read(salt)
	if err != nil{
		return
	}
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