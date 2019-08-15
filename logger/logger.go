package logger

import (
	"os"

	"github.com/Sirupsen/logrus"
)

func Init() {
	logrus.SetFormatter(&formatter{})
	logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.InfoLevel)
}
