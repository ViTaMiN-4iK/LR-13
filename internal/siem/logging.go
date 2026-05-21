package siem

import (
	"io"
	"log"
	"os"
)

func SetupLogging(agent string) func() {
	file, err := os.OpenFile(agent+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("file logging disabled: %v", err)
		return func() {}
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(io.MultiWriter(os.Stdout, file))
	return func() {
		_ = file.Close()
	}
}
