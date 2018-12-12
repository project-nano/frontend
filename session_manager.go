package main

type LoggedSession struct {
	ID string
	User string
	Menu []string
	Nonce string
	Key string
}


type SessionManager struct {
}

func CreateSessionManager()  (manager *SessionManager, err error){
	panic("not implement")
}

type SessionResult struct {
	Error       error
	Session     LoggedSession
	SessionList []LoggedSession
}

func (manager *SessionManager) AllocateSession(user, nonce string, menu []string, resp chan SessionResult) () {

}

func (manager *SessionManager) UpdateSession(session string, resp chan error) () {

}

func (manager *SessionManager) GetSession(session string, resp chan SessionResult) () {

}

func (manager *SessionManager) QuerySessions(resp chan SessionResult) () {

}