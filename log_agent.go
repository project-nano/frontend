package main

import (
	"time"
	"fmt"
	"os"
	"bufio"
	"log"
	"path/filepath"
)

type LogAgent struct {
	currentTime  time.Time
	currentIndex int
	currentFile  *os.File
	fileWriter   *bufio.Writer
	logRoot      string
}

const (
	EntryPrefixFormat = "20160102150405"
)

func (agent *LogAgent) Write(content string) (err error) {
	var now = time.Now()
	var entryTimeStamp = now.Round(time.Second)
	const (
		InitialIndex = 1
	)
	if entryTimeStamp.Equal(agent.currentTime) {
		agent.currentIndex++
	}else{
		if !now.Round(24*time.Hour).Equal(agent.currentTime.Round(24*time.Hour)){
			//open new file for a new day
			if err = agent.currentFile.Close();err != nil{
				return
			}
			if agent.currentFile, err = agent.createLogFile(now); err != nil{
				return
			}
			agent.fileWriter = bufio.NewWriter(agent.currentFile)
			log.Printf("<log> new log writer opened for %s", now.Format("2016-01-02"))
		}
		//reset mark to second.1
		agent.currentTime = entryTimeStamp
		agent.currentIndex = InitialIndex
	}

	var entryID = fmt.Sprintf("%s%03d", entryTimeStamp.Format(EntryPrefixFormat), agent.currentIndex)
	_, err = agent.fileWriter.WriteString(fmt.Sprintf("%s,%d,%s\n", entryID, now.UnixNano(), content))
	if err != nil{
		return
	}
	agent.fileWriter.Flush()
	return nil
}

func (agent *LogAgent) Remove(idList []string) (err error) {
	const (
		IndexLength       = 3
		DayFormat         = "20160102"
		MonthPrefixLength = 6
	)
	var targetMap = map[string]map[string]bool{}
	for _, entryID := range idList{
		if len(entryID) != (len(EntryPrefixFormat) + IndexLength){
			err = fmt.Errorf("invalid entry id '%s' with length %d", entryID, len(entryID))
			return
		}
		timeStamp, err := time.Parse(EntryPrefixFormat, entryID[:len(EntryPrefixFormat)])
		if err != nil{
			err = fmt.Errorf("invalid entry id prefix '%s'", entryID[:len(EntryPrefixFormat)])
			return
		}
		var dayString = timeStamp.Format(DayFormat)
		if _, exists := targetMap[dayString]; !exists{
			targetMap[dayString] = map[string]bool{entryID: true}
		}else{
			targetMap[dayString][entryID] = true
		}
	}
	for dayString, targets := range targetMap{
		var month = dayString[:MonthPrefixLength]
		var filePath = filepath.Join(agent.logRoot, month, fmt.Sprintf("%s.log", dayString))
		if _, err = os.Stat(filePath); os.IsNotExist(err){
			err = fmt.Errorf("can not find log file '%s'", filePath)
			return
		}
	}

	panic("not implement")
}

func (agent *LogAgent) Query(condition LogQueryCondition) (logs []LogEntry, err error) {
	panic("not implement")
}

func (agent *LogAgent) createLogFile(date time.Time) (file *os.File, err error){
	panic("not implement")
}