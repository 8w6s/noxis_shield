package logger

import (
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	log     *zap.SugaredLogger
	once    sync.Once
	logFile *os.File
)

// Init initializes the global logger
func Init(level, format, filePath string) error {
	var err error
	once.Do(func() {
		err = initLogger(level, format, filePath)
	})
	return err
}

func initLogger(level, format, filePath string) error {
	// Parse level
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	// Encoder config
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder

	var encoder zapcore.Encoder
	if format == "json" {
		encoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	}

	// Multi-writer: console + file
	writers := []zapcore.WriteSyncer{zapcore.AddSync(os.Stdout)}

	if filePath != "" {
		dir := filepath.Dir(filePath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		logFile = f
		writers = append(writers, zapcore.AddSync(f))
	}

	core := zapcore.NewCore(
		encoder,
		zapcore.NewMultiWriteSyncer(writers...),
		zapLevel,
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	log = logger.Sugar()
	return nil
}

// L returns the global logger
func L() *zap.SugaredLogger {
	if log == nil {
		// Fallback logger
		l, _ := zap.NewDevelopment()
		return l.Sugar()
	}
	return log
}

// Close gracefully closes the logger
func Close() {
	if log != nil {
		log.Sync()
	}
	if logFile != nil {
		logFile.Close()
	}
}

// --- Convenience functions ---

func Info(msg string, keysAndValues ...interface{})  { L().Infow(msg, keysAndValues...) }
func Warn(msg string, keysAndValues ...interface{})  { L().Warnw(msg, keysAndValues...) }
func Error(msg string, keysAndValues ...interface{}) { L().Errorw(msg, keysAndValues...) }
func Debug(msg string, keysAndValues ...interface{}) { L().Debugw(msg, keysAndValues...) }
func Fatal(msg string, keysAndValues ...interface{}) { L().Fatalw(msg, keysAndValues...) }
