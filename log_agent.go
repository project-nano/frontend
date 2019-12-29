package main

import (
	"time"
	"fmt"
	"os"
	"bufio"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"io"
)

type LogAgent struct {
	currentTime     time.Time
	currentIndex    int
	currentFile     *os.File
	currentLogPath  string
	fileWriter      *bufio.Writer
	logRoot         string
	logContent      []string //from new to old
	contentModified bool
}

const (
	EntryPrefixFormat  = "20060102150405"
	Day                = 24 * time.Hour
	MonthFormat        = "200601"
	DateFormat         = "20060102"
	ValidEntryIDLength = len(EntryPrefixFormat) + 3
	InitialEntryIndex  = 1
	OpenFilePerm       = 0640
)

func CreateLogAgent(dataPath string) (agent *LogAgent, err error) {
	const (
		logPathName     = "log"
		DefaultPathPerm = 0740
	)
	agent = &LogAgent{}
	agent.logContent = make([]string, 0)
	agent.contentModified = false
	agent.logRoot = filepath.Join(dataPath, logPathName)
	if _, err = os.Stat(agent.logRoot); os.IsNotExist(err){
		if err = os.MkdirAll(agent.logRoot, DefaultPathPerm); err != nil{
			return
		}
		log.Printf("<log> log root path '%s' created", agent.logRoot)
	}
	var today = time.Now().Truncate(Day)
	var monthPath = filepath.Join(agent.logRoot, today.Format(MonthFormat))
	agent.currentLogPath = filepath.Join(monthPath, fmt.Sprintf("%s.log", today.Format(DateFormat)))
	if _, err = os.Stat(agent.currentLogPath); os.IsNotExist(err){
		if _, err = os.Stat(monthPath); os.IsNotExist(err){
			if err = os.Mkdir(monthPath, DefaultPathPerm); err != nil{
				return
			}
			log.Printf("<log> new log path '%s' created", monthPath)
		}
		//today is a new day
		agent.currentTime = time.Now().Truncate(time.Second)
		agent.currentIndex = InitialEntryIndex
		err = agent.openCurrentLog()
		return
	}

	//load current
	var lastEntry LogEntry
	var entryAvailable = false

	{
		var scanSource *os.File
		scanSource, err = os.Open(agent.currentLogPath)
		if err != nil{
			return
		}
		defer scanSource.Close()
		var scanner = bufio.NewScanner(scanSource)
		for scanner.Scan(){
			var line = scanner.Text()
			agent.logContent = append(agent.logContent, line)
			if !entryAvailable{
				lastEntry, err = parseLog(line)
				if err != nil{
					return
				}
				entryAvailable = true
			}
		}

	}

	if entryAvailable{
		agent.currentTime = lastEntry.Time.Truncate(time.Second)
		agent.currentIndex, err = strconv.Atoi(lastEntry.ID[len(EntryPrefixFormat):])
		if err != nil{
			log.Printf("<log> parse index from entry '%s' fail: %s", lastEntry.ID, err.Error())
			return
		}
		log.Printf("<log> last entry '%s' (%d available) loaded from '%s'", lastEntry.ID, len(agent.logContent), agent.currentLogPath)

	}else{
		agent.currentTime = time.Now().Truncate(time.Second)
		agent.currentIndex = InitialEntryIndex
	}
	err = agent.openCurrentLog()
	return
}

func (agent *LogAgent) Write(content string) (err error) {
	var now = time.Now()
	var entryTimeStamp = now.Truncate(time.Second)
	var entry LogEntry
	if entryTimeStamp.Equal(agent.currentTime) {
		entry.ID = fmt.Sprintf("%s%03d", entryTimeStamp.Format(EntryPrefixFormat), agent.currentIndex)
		agent.currentIndex++
	}else{
		if !now.Truncate(24*time.Hour).Equal(agent.currentTime.Truncate(24*time.Hour)){
			//open new file for a new day
			if err = agent.Close(); err != nil{
				return
			}
			agent.currentLogPath = filepath.Join(agent.logRoot, now.Format(MonthFormat), fmt.Sprintf("%s.log", now.Format(DateFormat)))
			if err = agent.openCurrentLog(); err != nil{
				return
			}
			agent.logContent = make([]string, 0)
			agent.contentModified = false
		}
		//reset mark to second.1
		agent.currentTime = entryTimeStamp
		agent.currentIndex = InitialEntryIndex
		entry.ID = fmt.Sprintf("%s%03d", entryTimeStamp.Format(EntryPrefixFormat), agent.currentIndex)
	}
	entry.Time = now
	entry.Content = content
	//insert
	agent.logContent = append([]string{logToLine(entry)}, agent.logContent...)
	if !agent.contentModified{
		agent.contentModified = true
	}
	return nil
}

func (agent *LogAgent) Remove(idList []string) (err error) {
	const (
		IndexLength       = 3
		MonthPrefixLength = 6
	)
	var currentLocation = time.Now().Location()
	var targetMap = map[string]map[string]bool{}
	for _, entryID := range idList{
		if len(entryID) != (len(EntryPrefixFormat) + IndexLength){
			err = fmt.Errorf("invalid entry id '%s' with length %d", entryID, len(entryID))
			return
		}
		timeStamp, err := time.ParseInLocation(EntryPrefixFormat, entryID[:len(EntryPrefixFormat)], currentLocation)
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
		var isCurrentLog = logFilePath == agent.currentLogPath

		var logLines []string
		if isCurrentLog{
			logLines = agent.logContent
		}else{
			//load all entries
			var logFile *os.File
			logFile, err = os.Open(logFilePath)
			if err != nil{
				err = fmt.Errorf("open log file fail: %s", err.Error())
				return err
			}
			var logScanner = bufio.NewScanner(logFile)
			for logScanner.Scan() {
				logLines = append(logLines, logScanner.Text())
			}
			logFile.Close()
		}
		var removeResult = make([]string, 0)
		for _, line := range logLines{
			entry, err := parseLog(line)
			if err != nil{
				return err
			}
			if _, exists := targets[entry.ID]; exists{
				delete(targets, entry.ID)
				log.Printf("<log> entry '%s' removed from '%s'", entry.ID, logFilePath)
			}else{
				removeResult = append(removeResult, line)
			}
		}
		if isCurrentLog{
			agent.logContent = removeResult
			agent.contentModified = true
		}else{
			//rewrite all lines
			var logFile *os.File
			logFile, err = os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND|os.O_TRUNC, OpenFilePerm)
			if err != nil{
				err = fmt.Errorf("rewrite log file fail: %s", err.Error())
				return err
			}
			var writer = bufio.NewWriter(logFile)
			for _, line := range removeResult{
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
			log.Printf("<log> %d lines rewrite to '%s'", len(removeResult), logFilePath)
		}
	}
	log.Printf("<log> %d entries removed", len(idList))
	return nil
}

func (agent *LogAgent) Query(condition LogQueryCondition) (logs []LogEntry, total uint, err error) {
	const (
		MaxEntry = 1000
	)
	total = 0
	if condition.EndTime.Before(condition.BeginTime){
		err = fmt.Errorf("invalid time range (%s ~ %s)", condition.BeginTime.Format(TimeFormatLayout), condition.EndTime.Format(TimeFormatLayout))
		return
	}
	var queried, offset = 0, 0
	var inTimeRange = false
	for date := condition.EndTime; date.After(condition.BeginTime); date = date.Add(-Day){
		var logFilePath = filepath.Join(agent.logRoot, date.Format(MonthFormat), fmt.Sprintf("%s.log", date.Format(DateFormat)))

		var isCurrentLog = logFilePath == agent.currentLogPath
		var logLines []string
		if isCurrentLog{
			logLines = agent.logContent
			//log.Printf("<log> debug: %d lines loaded from current log", len(logLines))
		}else{
			if _, err = os.Stat(logFilePath); os.IsNotExist(err){
				//log.Printf("<log> warning: query ignores absent log '%s'", logFilePath)
				continue
			}
			var logFile *os.File
			logFile, err = os.Open(logFilePath)
			if err != nil{
				return
			}
			var scanner = bufio.NewScanner(logFile)
			for scanner.Scan(){
				logLines = append(logLines, scanner.Text())
			}
			logFile.Close()
		}


		for _, line := range logLines {
			var entry LogEntry
			entry, err = parseLog(line)
			if err != nil{
				log.Printf("<log> parse line %d of log '%s' fail: %s", offset, logFilePath, err.Error())
				return
			}
			if !inTimeRange {
				if entry.Time.Before(condition.EndTime){
					//range start
					inTimeRange = true
				}
			}
			if inTimeRange{
				if offset < condition.Start{
					total++
					offset++
					continue
				}
				if entry.Time.Before(condition.BeginTime){
					break
				}
				if total >= MaxEntry{
					break
				}
				total++
				if queried < condition.Limit{
					//store log
					logs = append(logs, entry)
					queried++
				}
			}
		}//end scanner
		if total >= MaxEntry{
			break
		}
	}
	//log.Printf("<log> %d / %d entries queried between (%s ~ %s), start from %d, with limit %d",
	//	len(logs), total,
	//	condition.BeginTime.Format(TimeFormatLayout),
	//	condition.EndTime.Format(TimeFormatLayout),
	//	condition.Start, condition.Limit)
	return logs, total,nil
}

func (agent *LogAgent) Flush() (err error){
	if !agent.contentModified{
		return nil
	}
	if _, err = agent.currentFile.Seek(0, io.SeekStart); err != nil{
		return
	}
	agent.fileWriter.Reset(agent.currentFile)
	for _, log := range agent.logContent{
		if _, err = agent.fileWriter.WriteString(log); err != nil{
			return
		}
		if _, err = agent.fileWriter.WriteString("\n"); err != nil{
			return
		}
	}
	if err = agent.fileWriter.Flush(); err != nil{
		return
	}
	agent.contentModified = false
	return nil
}

func (agent *LogAgent) Close() (err error){
	if err = agent.Flush(); err != nil{
		return
	}
	return agent.closeCurrentLog()
}

func (agent *LogAgent) openCurrentLog() (err error){
	if _, err = os.Stat(agent.currentLogPath); os.IsNotExist(err){
		agent.currentFile, err = os.Create(agent.currentLogPath)
		if err != nil{
			return
		}
		log.Printf("<log> current log '%s' created", agent.currentLogPath)
	}else{
		//open
		agent.currentFile, err = os.OpenFile(agent.currentLogPath, os.O_RDWR|os.O_CREATE, OpenFilePerm)
		if err != nil{
			return
		}
		log.Printf("<log> current log '%s' opened", agent.currentLogPath)
	}
	agent.fileWriter = bufio.NewWriter(agent.currentFile)
	return nil
}

func (agent *LogAgent) closeCurrentLog() (err error){
	if err = agent.fileWriter.Flush(); err != nil{
		return
	}
	if err = agent.currentFile.Close(); err != nil{
		return
	}
	agent.currentFile = nil
	log.Printf("<log> current log '%s' closed", agent.currentLogPath)
	return nil
}

func parseLog(line string) (entry LogEntry, err error) {
	const (
		separator = ","
	)
	var idTail = strings.Index(line, separator)
	if idTail <= 0 {
		err = fmt.Errorf("entry ID missed in line %s", line)
		return
	}
	if idTail != ValidEntryIDLength{
		err = fmt.Errorf("invalid entry ID '%s'", line[:idTail])
		return
	}
	entry.ID = line[:idTail]
	var timeTail = strings.Index(line[(idTail + 1):], separator)
	if timeTail <= 0{
		err = fmt.Errorf("entry time missed in line %s", line)
		return
	}

	var timeInString = line[(idTail + 1): (idTail + 1 + timeTail)]
	var unixnano int64
	unixnano, err = strconv.ParseInt(timeInString, 10, 64)
	if err != nil{
		err = fmt.Errorf("invalid time stamp '%s'", timeInString)
		return
	}
	entry.Time = time.Unix(0, unixnano)
	entry.Content = line[(idTail + timeTail + 2):]
	return entry, nil
}

func logToLine(entry LogEntry) (line string){
	return fmt.Sprintf("%s,%d,%s", entry.ID, entry.Time.UnixNano(), entry.Content)
}
