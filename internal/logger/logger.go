package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger 日志器接口
type Logger interface {
	Debug(msg string, fields ...zap.Field)
	Info(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
	Fatal(msg string, fields ...zap.Field)
	Panic(msg string, fields ...zap.Field)
	
	Debugf(template string, args ...interface{})
	Infof(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Errorf(template string, args ...interface{})
	Fatalf(template string, args ...interface{})
	Panicf(template string, args ...interface{})
	
	Debugw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	Fatalw(msg string, keysAndValues ...interface{})
	Panicw(msg string, keysAndValues ...interface{})
	
	With(fields ...zap.Field) Logger
	Named(name string) Logger
	Sync() error
}

// EDRLogger EDR日志器实现
type EDRLogger struct {
	logger *zap.Logger
	sugar  *zap.SugaredLogger
}

// LogConfig 日志配置
type LogConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

// NewLogger 创建新的日志器
func NewLogger(config LogConfig) (Logger, error) {
	// 解析日志级别
	level, err := parseLogLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("无效的日志级别: %s", config.Level)
	}

	// 创建编码器配置
	encoderConfig := getEncoderConfig(config.Format)

	// 创建编码器
	var encoder zapcore.Encoder
	switch strings.ToLower(config.Format) {
	case "json":
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	case "console", "text":
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	default:
		return nil, fmt.Errorf("不支持的日志格式: %s", config.Format)
	}

	// 创建写入器
	writeSyncer, err := getWriteSyncer(config)
	if err != nil {
		return nil, fmt.Errorf("创建日志写入器失败: %v", err)
	}

	// 创建核心
	core := zapcore.NewCore(encoder, writeSyncer, level)

	// 创建logger
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1), zap.AddStacktrace(zapcore.ErrorLevel))

	return &EDRLogger{
		logger: logger,
		sugar:  logger.Sugar(),
	}, nil
}

// parseLogLevel 解析日志级别
func parseLogLevel(level string) (zapcore.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	case "panic":
		return zapcore.PanicLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("未知的日志级别: %s", level)
	}
}

// getEncoderConfig 获取编码器配置
func getEncoderConfig(format string) zapcore.EncoderConfig {
	config := zap.NewProductionEncoderConfig()
	config.TimeKey = "timestamp"
	config.LevelKey = "level"
	config.NameKey = "logger"
	config.CallerKey = "caller"
	config.MessageKey = "message"
	config.StacktraceKey = "stacktrace"
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncodeLevel = zapcore.LowercaseLevelEncoder
	config.EncodeCaller = zapcore.ShortCallerEncoder
	
	if strings.ToLower(format) == "console" || strings.ToLower(format) == "text" {
		config.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncodeCaller = zapcore.FullCallerEncoder
	}
	
	return config
}

// getWriteSyncer 获取写入同步器
func getWriteSyncer(config LogConfig) (zapcore.WriteSyncer, error) {
	if config.Output == "" || config.Output == "stdout" {
		return zapcore.AddSync(os.Stdout), nil
	} else if config.Output == "stderr" {
		return zapcore.AddSync(os.Stderr), nil
	} else {
		// 文件输出，使用日志轮转
		dir := filepath.Dir(config.Output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("创建日志目录失败: %v", err)
		}

		lumberjackLogger := &lumberjack.Logger{
			Filename:   config.Output,
			MaxSize:    config.MaxSize,
			MaxBackups: config.MaxBackups,
			MaxAge:     config.MaxAge,
			Compress:   config.Compress,
		}

		return zapcore.AddSync(lumberjackLogger), nil
	}
}

// Debug 调试日志
func (l *EDRLogger) Debug(msg string, fields ...zap.Field) {
	l.logger.Debug(msg, fields...)
}

// Info 信息日志
func (l *EDRLogger) Info(msg string, fields ...zap.Field) {
	l.logger.Info(msg, fields...)
}

// Warn 警告日志
func (l *EDRLogger) Warn(msg string, fields ...zap.Field) {
	l.logger.Warn(msg, fields...)
}

// Error 错误日志
func (l *EDRLogger) Error(msg string, fields ...zap.Field) {
	l.logger.Error(msg, fields...)
}

// Fatal 致命错误日志
func (l *EDRLogger) Fatal(msg string, fields ...zap.Field) {
	l.logger.Fatal(msg, fields...)
}

// Panic panic日志
func (l *EDRLogger) Panic(msg string, fields ...zap.Field) {
	l.logger.Panic(msg, fields...)
}

// Debugf 格式化调试日志
func (l *EDRLogger) Debugf(template string, args ...interface{}) {
	l.sugar.Debugf(template, args...)
}

// Infof 格式化信息日志
func (l *EDRLogger) Infof(template string, args ...interface{}) {
	l.sugar.Infof(template, args...)
}

// Warnf 格式化警告日志
func (l *EDRLogger) Warnf(template string, args ...interface{}) {
	l.sugar.Warnf(template, args...)
}

// Errorf 格式化错误日志
func (l *EDRLogger) Errorf(template string, args ...interface{}) {
	l.sugar.Errorf(template, args...)
}

// Fatalf 格式化致命错误日志
func (l *EDRLogger) Fatalf(template string, args ...interface{}) {
	l.sugar.Fatalf(template, args...)
}

// Panicf 格式化panic日志
func (l *EDRLogger) Panicf(template string, args ...interface{}) {
	l.sugar.Panicf(template, args...)
}

// Debugw 结构化调试日志
func (l *EDRLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.sugar.Debugw(msg, keysAndValues...)
}

// Infow 结构化信息日志
func (l *EDRLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.sugar.Infow(msg, keysAndValues...)
}

// Warnw 结构化警告日志
func (l *EDRLogger) Warnw(msg string, keysAndValues ...interface{}) {
	l.sugar.Warnw(msg, keysAndValues...)
}

// Errorw 结构化错误日志
func (l *EDRLogger) Errorw(msg string, keysAndValues ...interface{}) {
	l.sugar.Errorw(msg, keysAndValues...)
}

// Fatalw 结构化致命错误日志
func (l *EDRLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	l.sugar.Fatalw(msg, keysAndValues...)
}

// Panicw 结构化panic日志
func (l *EDRLogger) Panicw(msg string, keysAndValues ...interface{}) {
	l.sugar.Panicw(msg, keysAndValues...)
}

// With 添加字段
func (l *EDRLogger) With(fields ...zap.Field) Logger {
	return &EDRLogger{
		logger: l.logger.With(fields...),
		sugar:  l.sugar.With(fields),
	}
}

// Named 创建命名日志器
func (l *EDRLogger) Named(name string) Logger {
	return &EDRLogger{
		logger: l.logger.Named(name),
		sugar:  l.sugar.Named(name),
	}
}

// Sync 同步日志
func (l *EDRLogger) Sync() error {
	return l.logger.Sync()
}

// 全局日志器
var globalLogger Logger

// InitGlobalLogger 初始化全局日志器
func InitGlobalLogger(config LogConfig) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	globalLogger = logger
	return nil
}

// GetLogger 获取全局日志器
func GetLogger() Logger {
	if globalLogger == nil {
		// 如果没有初始化，使用默认配置
		config := LogConfig{
			Level:  "info",
			Format: "console",
			Output: "stdout",
		}
		logger, _ := NewLogger(config)
		globalLogger = logger
	}
	return globalLogger
}

// SetGlobalLogger 设置全局日志器
func SetGlobalLogger(logger Logger) {
	globalLogger = logger
}

// Debug 全局调试日志
func Debug(msg string, fields ...zap.Field) {
	GetLogger().Debug(msg, fields...)
}

// Info 全局信息日志
func Info(msg string, fields ...zap.Field) {
	GetLogger().Info(msg, fields...)
}

// Warn 全局警告日志
func Warn(msg string, fields ...zap.Field) {
	GetLogger().Warn(msg, fields...)
}

// Error 全局错误日志
func Error(msg string, fields ...zap.Field) {
	GetLogger().Error(msg, fields...)
}

// Fatal 全局致命错误日志
func Fatal(msg string, fields ...zap.Field) {
	GetLogger().Fatal(msg, fields...)
}

// Panic 全局panic日志
func Panic(msg string, fields ...zap.Field) {
	GetLogger().Panic(msg, fields...)
}

// Debugf 全局格式化调试日志
func Debugf(template string, args ...interface{}) {
	GetLogger().Debugf(template, args...)
}

// Infof 全局格式化信息日志
func Infof(template string, args ...interface{}) {
	GetLogger().Infof(template, args...)
}

// Warnf 全局格式化警告日志
func Warnf(template string, args ...interface{}) {
	GetLogger().Warnf(template, args...)
}

// Errorf 全局格式化错误日志
func Errorf(template string, args ...interface{}) {
	GetLogger().Errorf(template, args...)
}

// Fatalf 全局格式化致命错误日志
func Fatalf(template string, args ...interface{}) {
	GetLogger().Fatalf(template, args...)
}

// Panicf 全局格式化panic日志
func Panicf(template string, args ...interface{}) {
	GetLogger().Panicf(template, args...)
}

// Debugw 全局结构化调试日志
func Debugw(msg string, keysAndValues ...interface{}) {
	GetLogger().Debugw(msg, keysAndValues...)
}

// Infow 全局结构化信息日志
func Infow(msg string, keysAndValues ...interface{}) {
	GetLogger().Infow(msg, keysAndValues...)
}

// Warnw 全局结构化警告日志
func Warnw(msg string, keysAndValues ...interface{}) {
	GetLogger().Warnw(msg, keysAndValues...)
}

// Errorw 全局结构化错误日志
func Errorw(msg string, keysAndValues ...interface{}) {
	GetLogger().Errorw(msg, keysAndValues...)
}

// Fatalw 全局结构化致命错误日志
func Fatalw(msg string, keysAndValues ...interface{}) {
	GetLogger().Fatalw(msg, keysAndValues...)
}

// Panicw 全局结构化panic日志
func Panicw(msg string, keysAndValues ...interface{}) {
	GetLogger().Panicw(msg, keysAndValues...)
}

// With 全局添加字段
func With(fields ...zap.Field) Logger {
	return GetLogger().With(fields...)
}

// Named 全局创建命名日志器
func Named(name string) Logger {
	return GetLogger().Named(name)
}

// Sync 全局同步日志
func Sync() error {
	return GetLogger().Sync()
}

// 便捷的字段创建函数
var (
	String   = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Float64  = zap.Float64
	Bool     = zap.Bool
	Time     = zap.Time
	Duration = zap.Duration
	ErrorField = zap.Error
	Any      = zap.Any
) 