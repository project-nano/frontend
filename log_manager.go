package main

import "time"

type LogManager struct {

}

type LogQueryCondition struct {
	Limit uint
	Start uint
	After time.Time
	Before time.Time
}

type LogEntry struct {
	ID string `json:"id"`
	Time
}

type LogResult struct {

}

func CreateLogManager(dataPath string) (manager *LogManager, err error) {
	panic("not implement")
}

func (manager *LogManager) QueryLog(condition LogQueryCondition, respChan chan LogResult)  {

}

func (manager *LogManager) AddLog(content string, respChan chan error)  {

}

func (manager *LogManager) RemoveLog(entries []string, respChan chan error)  {

}
