package main

import (
	"github.com/project-nano/framework"
	"log"
	"fmt"
	"time"
	"github.com/satori/go.uuid"
)

type LoggedSession struct {
	ID      string
	User    string
	Group   string
	Menu    []string
	Nonce   string
	Key     string
	Expire  time.Time
	Timeout int
	Address string
}

type sessionCommandType int

const (
	cmdAllocateSession = iota
	cmdUpdateSession
	cmdGetSession
	cmdQuerySession
)

type sessionCMD struct {
	Type       sessionCommandType
	User       string
	Group      string
	Nonce      string
	Menu       []string
	Session    string
	Address    string
	ResultChan chan SessionResult
	ErrorChan  chan error
}

type SessionResult struct {
	Error       error
	Session     LoggedSession
	SessionList []LoggedSession
}

type SessionManager struct {
	sessions map[string]LoggedSession
	commands chan sessionCMD
	runner   *framework.SimpleRunner
}

const (
	DefaultSessionTimeout = 3 * time.Minute
)

func CreateSessionManager() (manager *SessionManager, err error) {
	manager = &SessionManager{}
	manager.sessions = map[string]LoggedSession{}
	manager.commands = make(chan sessionCMD, 1<<10)
	manager.runner = framework.CreateSimpleRunner(manager.Routine)
	return
}

func (manager *SessionManager) Start() error{
	return manager.runner.Start()
}

func (manager *SessionManager) Stop() error{
	return manager.runner.Stop()
}

func (manager *SessionManager) Routine(c framework.RoutineController) {
	const (
		TimerInterval = 10 * time.Second
	)
	log.Println("<session> started")
	var ticker = time.NewTicker(TimerInterval)
	for !c.IsStopping() {
		select {
		case <-c.GetNotifyChannel():
			c.SetStopping()
		case cmd := <-manager.commands:
			manager.handleCommand(cmd)
		case <-ticker.C:
			manager.checkTimeout()
		}
	}
	c.NotifyExit()
	log.Println("<session> stopped")
}

func (manager *SessionManager) AllocateSession(user, group, nonce, address string, menu []string, resp chan SessionResult) {
	manager.commands <- sessionCMD{Type: cmdAllocateSession, User: user, Group:group, Nonce: nonce, Address: address, Menu: menu, ResultChan: resp}
}

func (manager *SessionManager) UpdateSession(session string, resp chan error) {
	manager.commands <- sessionCMD{Type: cmdUpdateSession, Session: session, ErrorChan: resp}
}

func (manager *SessionManager) GetSession(session string, resp chan SessionResult) {
	manager.commands <- sessionCMD{Type: cmdGetSession, Session: session, ResultChan: resp}
}

func (manager *SessionManager) QuerySessions(resp chan SessionResult) {
	manager.commands <- sessionCMD{Type: cmdQuerySession, ResultChan: resp}
}

func (manager *SessionManager) handleCommand(cmd sessionCMD) {
	var err error
	switch cmd.Type {
	case cmdAllocateSession:
		err = manager.handleAllocateSession(cmd.User, cmd.Group, cmd.Nonce, cmd.Address, cmd.Menu, cmd.ResultChan)
	case cmdGetSession:
		err = manager.handleGetSession(cmd.Session, cmd.ResultChan)
	case cmdUpdateSession:
		err = manager.handleUpdateSession(cmd.Session, cmd.ErrorChan)
	case cmdQuerySession:
		err = manager.handleQuerySessions(cmd.ResultChan)
	default:
		log.Printf("<session> unsupport command type %d", cmd.Type)
		return
	}
	if err != nil{
		log.Printf("<session> handle command type %d fail: %s", cmd.Type, err.Error())
	}
}

func (manager *SessionManager) handleAllocateSession(user, group, nonce, address string, menu []string, resp chan SessionResult) (err error) {

	var session = LoggedSession{}
	var UID = uuid.NewV4()
	session.ID = UID.String()
	session.User = user
	session.Group = group
	session.Nonce = nonce
	session.Menu = menu
	session.Address = address
	session.Timeout = int(DefaultSessionTimeout / time.Second)
	session.Expire = time.Now().Add(DefaultSessionTimeout)
	manager.sessions[session.ID] = session
	resp <- SessionResult{Session:session}
	log.Printf("<session> new session '%s' allocated with user '%s.%s', remote address %s", session.ID, group, user, address)
	return nil
}

func (manager *SessionManager) handleUpdateSession(sessionID string, resp chan error) (err error) {
	session, exists := manager.sessions[sessionID]
	if !exists{
		err = fmt.Errorf("invalid session '%s'", sessionID)
		resp <- err
		return err
	}
	session.Expire = time.Now().Add(DefaultSessionTimeout)
	manager.sessions[session.ID] = session
	resp <- nil
	return nil
}

func (manager *SessionManager) handleGetSession(sessionID string, resp chan SessionResult) (err error) {
	session, exists := manager.sessions[sessionID]
	if !exists{
		err = fmt.Errorf("invalid session '%s'", sessionID)
		resp <- SessionResult{Error:err}
		return err
	}
	resp <- SessionResult{Session:session}
	return nil
}

func (manager *SessionManager) handleQuerySessions(resp chan SessionResult) (err error) {
	var result = make([]LoggedSession, 0)
	for _, session := range manager.sessions{
		result = append(result, session)
	}
	resp <- SessionResult{SessionList:result}
	return nil
}

func (manager *SessionManager) checkTimeout(){
	var now = time.Now()
	var timeoutList []string
	for id, session := range manager.sessions{
		if session.Expire.Before(now){
			timeoutList = append(timeoutList, id)
		}
	}
	for _, id := range timeoutList{
		if _, exists := manager.sessions[id];exists{
			delete(manager.sessions, id)
			log.Printf("<session> timeout session '%s' removed", id)
		}
	}
}