package main

import (
	"time"
	"fmt"
	"os"
	"bufio"
	"log"
	"path/filepath"
	"strconv"
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
	Day               = 24 * time.Hour
	MonthFormat       = "201601"
	DateFormat        = "20160102"
)

func CreateLogAgent(dataPath string) (agent *LogAgent, err error) {
	const (
		logPathName     = "log"
		DefaultPathPerm = 0740
	)
	agent = &LogAgent{}
	agent.logRoot = filepath.Join(dataPath, logPathName)
	if _, err = os.Stat(agent.logRoot); os.IsNotExist(err){
		if err = os.MkdirAll(agent.logRoot, DefaultPathPerm); err != nil{
			return
		}
		log.Printf("<log> log root path '%s' created", agent.logRoot)
	}
	var today = time.Now().Round(Day)
	var logFilePath = filepath.Join(agent.logRoot, today.Format(MonthFormat), fmt.Sprintf("%s.log", today.Format(DateFormat)))
	if _, err = os.Stat(logFilePath); os.IsNotExist(err){
		//today is a new day
		agent.currentTime = time.Now()
		agent.currentIndex = 0
		agent.currentFile, err = os.Create(logFilePath)
		if err != nil{
			return
		}
		agent.fileWriter = bufio.NewWriter(agent.currentFile)
		log.Printf("<log> new log file '%s' created", logFilePath)
		return
	}
	//load current
	agent.currentFile, err = os.Open(logFilePath)
	if err != nil{
		return
	}
	var scanner = bufio.NewScanner(agent.currentFile)
	var lastEntry LogEntry
	for scanner.Scan(){
		lastEntry, err = parseLog(scanner.Text())
		if err != nil{
			return
		}
	}

	agent.currentTime = lastEntry.Time
	agent.currentIndex, err = strconv.Atoi(lastEntry.ID[len(EntryPrefixFormat):])
	if err != nil{
		log.Printf("<log> parse index from entry '%s' fail: %s", lastEntry.ID, err.Error())
		return
	}
	agent.fileWriter = bufio.NewWriter(agent.currentFile)
	log.Printf("<log> last entry '%s' loaded from '%s'", lastEntry.ID, logFilePath)
	return
}

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
	var entry LogEntry
	entry.ID = fmt.Sprintf("%s%03d", entryTimeStamp.Format(EntryPrefixFormat), agent.currentIndex)
	entry.Time = now
	entry.Content = content
	_, err = agent.fileWriter.WriteString(logToLine(entry))
	if err != nil{
		return
	}
	agent.fileWriter.Flush()
	return nil
}

func (agent *LogAgent) Remove(idList []string) (err error) {
	const (
		IndexLength       = 3
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
			return err
		}
		var dayString = timeStamp.Format(DateFormat)
		if _, exists := targetMap[dayString]; !exists{
			targetMap[dayString] = map[string]bool{entryID: true}
		}else{
			targetMap[dayString][entryID] = true
		}
	}
	for dayString, targets := range targetMap{
		var month = dayString[:MonthPrefixLength]
		var logFilePath = filepath.Join(agent.logRoot, month, fmt.Sprintf("%s.log", dayString))
		if _, err = os.Stat(logFilePath); os.IsNotExist(err){
			err = fmt.Errorf("can not find log file '%s'", logFilePath)
			return
		}

		var logLines []string
		{
			//load all entries
			logFile, err := os.Open(logFilePath)
			if err != nil{
				err = fmt.Errorf("open log file fail: %s", err.Error())
				return err
			}
			var logScanner = bufio.NewScanner(logFile)
			for logScanner.Scan(){
				var line = logScanner.Text()
				entry, err := parseLog(line)
				if err != nil{
					return err
				}
				if _, exists := targets[entry.ID]; exists{
					delete(targets, entry.ID)
					log.Printf("<log> entry '%s' removed from '%s'", entry.ID, logFilePath)
				}else{
					logLines = append(logLines, line)
				}
			}
			logFile.Close()
		}
		//rewrite all lines
		{
			logFile, err := os.Create(logFilePath)
			if err != nil{
				err = fmt.Errorf("rewrite log file fail: %s", err.Error())
				return err
			}
			var writer = bufio.NewWriter(logFile)
			for _, line := range logLines{
				_, err = writer.WriteString(line)
				if err != nil{
					return err
				}
				if err = writer.WriteByte('\n'); err != nil{
					return err
				}
			}
			writer.Flush()
			logFile.Close()
			log.Printf("<log> %d lines rewrite to '%s'", len(logLines), logFilePath)
		}
	}
	log.Printf("<log> %d entries removed", len(idList))
	return nil
}

func (agent *LogAgent) Query(condition LogQueryCondition) (logs []LogEntry, err error) {
	if condition.BeginTime.After(condition.EndTime){
		err = fmt.Errorf("invalid time range (%s ~ %s)", condition.BeginTime.Format(TimeFormatLayout), condition.EndTime.Format(TimeFormatLayout))
		return
	}
	var queried, offset = 0, 0
	var inTimeRange = false
	for date := condition.BeginTime; date.Before(condition.EndTime); date = date.Add(Day){
		var logFilePath = filepath.Join(agent.logRoot, date.Format(MonthFormat), fmt.Sprintf("%s.log", date.Format(DateFormat)))
		if _, err = os.Stat(logFilePath); os.IsNotExist(err){
			log.Printf("<log> warning: query ignores absent log '%s'", logFilePath)
			continue
		}
		var logFile *os.File
		logFile, err = os.Open(logFilePath)
		if err != nil{
			return
		}
		var scanner = bufio.NewScanner(logFile)
		for scanner.Scan(){
			var entry LogEntry
			entry, err = parseLog(scanner.Text())
			if err != nil{
				log.Printf("<log> parse line %d of log '%s' fail: %s", offset, logFilePath, err.Error())
				return
			}
			if !inTimeRange {
				if entry.Time.After(condition.BeginTime){
					//range start
					inTimeRange = true
					log.Printf("<log> debug: entry begin time at '%s'", entry.ID)
				}
			}
			if inTimeRange{
				if offset < condition.Start{
					//pass current entry
					log.Printf("<log> debug: pass entry '%s' at offset %d", entry.ID, offset)
					offset++
					continue
				}
				//store log
				logs = append(logs, entry)
				queried++
				log.Printf("<log> debug: entry '%s' queried", entry.ID)
				//check limit
				if queried >= condition.Limit{
					log.Printf("<log> debug: %d entries queried as '%s'", len(logs), logFilePath)
					break
				}
			}
		}//end scanner
		if queried >= condition.Limit{
			log.Printf("<log> debug: %d entries queried at date '%s'", len(logs), date.Format(DateFormat))
			break
		}
	}
	log.Printf("<log> %d entries queried", len(logs))
	return logs, nil
}

func (agent *LogAgent) createLogFile(date time.Time) (file *os.File, err error){
	var logFilePath = filepath.Join(agent.logRoot, date.Format(MonthFormat), fmt.Sprintf("%s.log", date.Format(DateFormat)))
	return os.Create(logFilePath)
}

func parseLog(line string) (entry LogEntry, err error) {
	panic("not implement")
}

func logToLine(entry LogEntry) (line string){
	return fmt.Sprintf("%s,%d,%s\n", entry.ID, entry.Time.UnixNano(), entry.Content)
}
