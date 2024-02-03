package tools

import (
	"time"
)

func GetDatetime() string {
	now := time.Now()
	return now.Format("2006-01-02 15:04:05")
}

func GetDatetimeMilSec() string {
	now := time.Now()
	return now.Format("2006-01-02 15:04:05.999")
}
