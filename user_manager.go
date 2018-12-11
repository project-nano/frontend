package main

type UserManager struct {

}

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
	Name           string `json:"name"`
	Nick           string `json:"nick,omitempty"`
	Mail           string `json:"mail,omitempty"`
	Group          string `json:"group,omitempty"`
	SaltedPassword string `json:"salted_password"`
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


func CreateUserManager()  (manager *UserManager, err error){
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
