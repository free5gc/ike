package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/logger_conf"
	logger_util "github.com/free5gc/util/logger"
)

var log *logrus.Logger

var (
	MsgLog   *logrus.Entry
	SecLog   *logrus.Entry
	DHLog    *logrus.Entry
	ENCRLog  *logrus.Entry
	ESNLog   *logrus.Entry
	INTEGLog *logrus.Entry
	PRFLog   *logrus.Entry
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	free5gcLogHook, err := logger_util.NewFileHook(logger_conf.Free5gcLogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
	if err == nil {
		log.Hooks.Add(free5gcLogHook)
	}

	selfLogHook, err := logger_util.NewFileHook(logger_conf.NfLogDir+"n3iwf.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
	if err == nil {
		log.Hooks.Add(selfLogHook)
	}

	MsgLog = log.WithFields(logrus.Fields{"component": "IKE", "category": "Message"})
	SecLog = log.WithFields(logrus.Fields{"component": "IKE", "category": "Security"})
	DHLog = log.WithFields(logrus.Fields{"component": "IKE", "category": "DH"})
	ENCRLog = log.WithFields(logrus.Fields{"component": "IKE", "category": "ENCR"})
	ESNLog = log.WithFields(logrus.Fields{"component": "IKE", "category": "ESN"})
	INTEGLog = log.WithFields(logrus.Fields{"component": "IKE", "category": "INTEG"})
	ESNLog = log.WithFields(logrus.Fields{"component": "IKE", "category": "ESN"})
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(set bool) {
	log.SetReportCaller(set)
}
