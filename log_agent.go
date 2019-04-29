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
)

type LogAgent struct {
	currentTime  time.Time
	currentIndex int
	currentFile  *os.File
	fileWriter   *bufio.Writer
	logRoot      string
}

const (
	EntryPrefixFormat  = "20060102150405"
	Day                = 24 * time.Hour
	MonthFormat        = "200601"
	DateFormat         = "20060102"
	ValidEntryIDLength = len(EntryPrefixFormat) + 3
	InitialEntryIndex  = 1
)

func CreateLogAgent(dataPath string) (agent *LogAgent, err error) {
	const (
		logPathName     = "log"
		DefaultPathPerm = 0740
		OpenFilePerm    = 0640
	)
	agent = &LogAgent{}
	agent.logRoot = filepath.Join(dataPath, logPathName)
	if _, err = os.Stat(agent.logRoot); os.IsNotExist(err){
		if err = os.MkdirAll(agent.logRoot, DefaultPathPerm); err != nil{
			return
		}
		log.Printf("<log> log root path '%s' created", agent.logRoot)
	}
	var today = time.Now().Truncate(Day)
	var monthPath = filepath.Join(agent.logRoot, today.Format(MonthFormat))
	var logFilePath = filepath.Join(monthPath, fmt.Sprintf("%s.log", today.Format(DateFormat)))
	if _, err = os.Stat(logFilePath); os.IsNotExist(err){
		if _, err = os.Stat(monthPath); os.IsNotExist(err){
			if err = os.Mkdir(monthPath, DefaultPathPerm); err != nil{
				return
			}
			log.Printf("<log> new log path '%s' created", monthPath)
		}
		//today is a new day
		agent.currentTime = time.Now().Truncate(time.Second)
		agent.currentIndex = InitialEntryIndex
		agent.currentFile, err = os.Create(logFilePath)
		if err != nil{
			return
		}
		agent.fileWriter = bufio.NewWriter(agent.currentFile)
		log.Printf("<log> new log file '%s' created", logFilePath)
		return
	}

	//load current
	var lastEntry LogEntry
	var entryAvailable = false

	{
		var scanSource *os.File
		scanSource, err = os.Open(logFilePath)
		if err != nil{
			return
		}
		var scanner = bufio.NewScanner(scanSource)
		for scanner.Scan(){
			lastEntry, err = parseLog(scanner.Text())
			if err != nil{
				return
			}
			if !entryAvailable{
				entryAvailable = true
			}
		}
	}
	agent.currentFile, err = os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND, OpenFilePerm)
	if err != nil{
		return
	}

	if entryAvailable{
		agent.currentTime = lastEntry.Time.Truncate(time.Second)
		agent.currentIndex, err = strconv.Atoi(lastEntry.ID[len(EntryPrefixFormat):])
		if err != nil{
			log.Printf("<log> parse index from entry '%s' fail: %s", lastEntry.ID, err.Error())
			return
		}
		log.Printf("<log> last entry '%s' loaded from '%s'", lastEntry.ID, logFilePath)

	}else{
		agent.currentTime = time.Now().Truncate(time.Second)
		agent.currentIndex = InitialEntryIndex
		log.Printf("<log> debug: initial to %s.%d", agent.currentTime.Format(TimeFormatLayout), agent.currentIndex)
	}

	agent.fileWriter = bufio.NewWriter(agent.currentFile)

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
			if err = agent.currentFile.Close();err != nil{
				return
			}
			if agent.currentFile, err = agent.createLogFile(now); err != nil{
				return
			}
			agent.fileWriter = bufio.NewWriter(agent.currentFile)
			log.Printf("<log> new log writer opened for %s", now.Format("2006-01-02"))
		}
		//reset mark to second.1
		agent.currentTime = entryTimeStamp
		agent.currentIndex = InitialEntryIndex
		entry.ID = fmt.Sprintf("%s%03d", entryTimeStamp.Format(EntryPrefixFormat), agent.currentIndex)
	}
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
	log.Printf("<log> debug: query limit %d, offset %d, begin %s/%d, end %s/%d",
		condition.Limit, condition.Start,
		condition.BeginTime.Format(TimeFormatLayout), condition.BeginTime.UnixNano(),
		condition.EndTime.Format(TimeFormatLayout), condition.EndTime.UnixNano())
	if condition.EndTime.Sub(condition.BeginTime) < 0{
		err = fmt.Errorf("invalid time range (%s ~ %s)", condition.BeginTime.Format(TimeFormatLayout), condition.EndTime.Format(TimeFormatLayout))
		return
	}
	var queried, offset = 0, 0
	var inTimeRange = false
	var endDate = condition.EndTime.Add(Day)
	for date := condition.BeginTime; date.Before(endDate); date = date.Add(Day){
		var logFilePath = filepath.Join(agent.logRoot, date.Format(MonthFormat), fmt.Sprintf("%s.log", date.Format(DateFormat)))
		if _, err = os.Stat(logFilePath); os.IsNotExist(err){
			log.Printf("<log> warning: query ignores absent log '%s'", logFilePath)
			continue
		}
		log.Printf("<log> debug: check file %s", logFilePath)
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
				log.Printf("<log> debug: out of range before check entry '%s', entry '%s', begin '%s'",
					entry.ID, entry.Time.Format(TimeFormatLayout), condition.BeginTime.Format(TimeFormatLayout))
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
	return fmt.Sprintf("%s,%d,%s\n", entry.ID, entry.Time.UnixNano(), entry.Content)
}
