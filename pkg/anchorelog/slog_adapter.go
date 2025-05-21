package anchorelogger

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/anchore/go-logger"
)

// Assertion that our adapter satisfies their interface.
var _ logger.Logger = (*SlogAdapter)(nil)

// SlogAdapter wraps a standard Go `*slog.Logger` to implement Anchore's
// proprietary logging interface, which is consumed by Syft and Grype.
type SlogAdapter struct {
	logger *slog.Logger
}

func NewSlogAdapter(slogger *slog.Logger) *SlogAdapter {
	return &SlogAdapter{logger: slogger}
}

func (s *SlogAdapter) log(level func(msg string, args ...any), args ...interface{}) {
	if len(args) == 0 {
		return
	}
	msg := fmt.Sprint(args...)

	// Specialized adjustment for messages heading into our logging system.
	if strings.HasPrefix(msg, "task completed") {
		// This one gets pretty noisy.
		level = s.logger.Debug
	}

	level(msg)
}

func (s *SlogAdapter) Errorf(format string, args ...interface{}) {
	s.logger.Error(fmt.Sprintf(format, args...))
}

func (s *SlogAdapter) Error(args ...interface{}) {
	s.log(s.logger.Error, args...)
}

func (s *SlogAdapter) Warnf(format string, args ...interface{}) {
	s.logger.Warn(fmt.Sprintf(format, args...))
}

func (s *SlogAdapter) Warn(args ...interface{}) {
	s.log(s.logger.Warn, args...)
}

func (s *SlogAdapter) Infof(format string, args ...interface{}) {
	s.logger.Info(fmt.Sprintf(format, args...))
}

func (s *SlogAdapter) Info(args ...interface{}) {
	s.log(s.logger.Info, args...)
}

func (s *SlogAdapter) Debugf(format string, args ...interface{}) {
	s.logger.Debug(fmt.Sprintf(format, args...))
}

func (s *SlogAdapter) Debug(args ...interface{}) {
	s.log(s.logger.Debug, args...)
}

func (s *SlogAdapter) Tracef(format string, args ...interface{}) {
	s.logger.Debug(fmt.Sprintf(format, args...))
}

func (s *SlogAdapter) Trace(args ...interface{}) {
	s.log(s.logger.Debug, args...)
}

func (s *SlogAdapter) WithFields(fields ...interface{}) logger.MessageLogger {
	attrs := make([]slog.Attr, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue // Skip malformed pairs
		}
		attrs = append(attrs, slog.Any(key, fields[i+1]))
	}
	args := make([]any, len(attrs))
	for i, attr := range attrs {
		args[i] = attr
	}
	return &SlogAdapter{logger: s.logger.With(args...)}
}

func (s *SlogAdapter) Nested(fields ...interface{}) logger.Logger {
	l, ok := s.WithFields(fields...).(logger.Logger)
	if !ok {
		panic("the Anchore slog adapter has been mis-implemented, and WithFields is returning a type that doesn't conform to logger.Logger")
	}
	return l
}

func (s *SlogAdapter) SetOutput(_ io.Writer) {
	// No-op; slog.Logger doesn't support changing output dynamically.
}

func (s *SlogAdapter) GetOutput() io.Writer {
	return nil // Not applicable
}
