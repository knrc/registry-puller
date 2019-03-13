package webhook

import (
	"log"
	"os"
)

const (
	logFlags = log.Ldate | log.Ltime | log.Lshortfile
)

var (
	logError = log.New(os.Stderr, "ERROR: ", logFlags)
	logInfo = log.New(os.Stdout, "INFO: ", logFlags)
)
