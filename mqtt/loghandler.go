package mqtt

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttLogger struct {
	logger  *slog.Logger
	level   slog.Level
	pattern *regexp.Regexp
}

func NewMQTTLogger(log *slog.Logger, level slog.Level) mqtt.Logger {
	r, _ := regexp.Compile(`^\[([A-Za-z]+)\]\s+(.+?)$`)
	return &mqttLogger{
		logger:  log,
		level:   level,
		pattern: r,
	}
}

func (l *mqttLogger) Println(v ...any) {
	l.doLog(fmt.Sprintln(v...))

}
func (l *mqttLogger) Printf(format string, v ...any) {
	l.doLog(fmt.Sprintf(format, v...))
}

func (l *mqttLogger) doLog(s string) {
	s = strings.TrimSpace(s)
	if mod, mess := l.ExtractModule(s); mod != "" {
		l.logger.Log(context.Background(), l.level, mess, "mqtt_module", mod)
	} else {
		l.logger.Log(context.Background(), l.level, mess)
	}
}

func (l *mqttLogger) ExtractModule(s string) (module string, message string) {
	if m := l.pattern.FindStringSubmatch(s); m != nil {
		return m[1], m[2]
	}
	return "", s
}
