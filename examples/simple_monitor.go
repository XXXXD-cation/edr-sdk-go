package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ccnochch/edr-sdk-go/internal/logger"
	"github.com/ccnochch/edr-sdk-go/pkg/monitoring"
	"go.uber.org/zap"
)

func main() {
	// 初始化日志
	logConfig := logger.LogConfig{
		Level:  "info",
		Format: "console",
		Output: "stdout",
	}

	if err := logger.InitGlobalLogger(logConfig); err != nil {
		log.Fatalf("初始化日志失败: %v", err)
	}

	log := logger.GetLogger()
	log.Info("启动简单进程监控示例")

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建进程监控器
	config := monitoring.ProcessMonitorConfig{
		Enabled:    true,
		Interval:   time.Second * 3,
		BufferSize: 100,
		Whitelist:  []string{},
		Blacklist:  []string{"kthreadd", "ksoftirqd", "migration"},
	}

	monitor := monitoring.NewProcessMonitor(config)

	// 启动监控
	if err := monitor.Start(ctx); err != nil {
		log.Fatal("启动进程监控失败", zap.Error(err))
	}

	// 启动事件处理协程
	go handleEvents(monitor, log)

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Info("进程监控已启动，按 Ctrl+C 退出")

	// 等待信号
	<-sigChan
	log.Info("收到退出信号，正在停止监控...")

	// 停止监控
	cancel()
	if err := monitor.Stop(); err != nil {
		log.Error("停止监控失败", zap.Error(err))
	}

	log.Info("监控已停止")
}

func handleEvents(monitor *monitoring.ProcessMonitor, log logger.Logger) {
	eventChan := monitor.GetEventChannel()

	for event := range eventChan {
		// 打印事件信息
		log.Info("进程事件",
			zap.String("type", event.Type),
			zap.Int("pid", event.PID),
			zap.Int("ppid", event.PPID),
			zap.String("name", event.Name),
			zap.String("cmdline", truncateString(event.Cmdline, 50)),
			zap.String("exe", event.Exe),
			zap.Int("uid", event.UID),
			zap.Int("gid", event.GID),
			zap.Time("start_time", event.StartTime),
			zap.String("start_time_formatted", event.StartTime.Format("2006-01-02 15:04:05")),
		)

		// 检查可疑活动
		if isSuspicious(event) {
			log.Warn("检测到可疑进程活动",
				zap.String("type", event.Type),
				zap.Int("pid", event.PID),
				zap.String("name", event.Name),
				zap.String("cmdline", event.Cmdline),
				zap.String("start_time", event.StartTime.Format("2006-01-02 15:04:05")),
			)
		}
	}
}

func isSuspicious(event monitoring.ProcessEvent) bool {
	// 简单的可疑活动检测
	suspiciousNames := []string{
		"nc", "netcat", "ncat",
		"wget", "curl",
		"python", "perl", "ruby",
	}

	for _, name := range suspiciousNames {
		if event.Name == name {
			return true
		}
	}

	return false
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
} 