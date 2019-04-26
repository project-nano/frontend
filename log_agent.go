package main

import "time"

type LogAgent struct {
	currentTime  time.Time
	currentIndex int
}

func (agent *LogAgent) Write(content string) (err error) {
	panic("not implement")
}