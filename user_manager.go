package main

type UserManager struct {

}

type UserRole struct {
	Name string   `json:"name"`
	Menu []string `json:"menu,omitempty"`
}

type UserGroup struct {
	Name string
	Roles []string
	Members map[string]bool
}

type User struct {
	Name           string `json:"name"`
	Mail           string `json:"mail,omitempty"`
	Group          string `json:"group,omitempty"`
	SaltedPassword string `json:"salted_password"`
}


type UserResult struct {
	Error error
	Role UserRole
	RoleList []UserRole
	Group UserGroup
	GroupList []UserGroup
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

func (manager *UserManager) RemoveRole(name string, resp chan error)  {

}