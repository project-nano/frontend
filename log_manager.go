package main

type LogManager struct {

}

type LogQueryCondition struct {

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
