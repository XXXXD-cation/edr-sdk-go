package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
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
		Level:  "debug",
		Format: "console",
		Output: "stdout",
	}

	if err := logger.InitGlobalLogger(logConfig); err != nil {
		log.Fatalf("初始化日志失败: %v", err)
	}

	log := logger.GetLogger()
	log.Info("启动进程时间异常检测测试")

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建进程监控器 - 标准配置
	stdConfig := monitoring.ProcessMonitorConfig{
		Enabled:         true,
		Interval:        time.Second * 3,
		BufferSize:      100,
		Whitelist:       []string{},
		Blacklist:       []string{"kthreadd", "ksoftirqd", "migration"},
		TimeZone:        "Asia/Shanghai",  // 使用上海时区
		TimeFormat:      "2006-01-02 15:04:05 MST",
		AnomalyDetection: true,
		MaxStartupDelay: 30 * time.Minute, // 设置更短的延迟检测，便于测试
	}

	log.Info("创建进程监控器 - 标准配置",
		zap.String("time_zone", stdConfig.TimeZone),
		zap.String("time_format", stdConfig.TimeFormat),
		zap.Bool("anomaly_detection", stdConfig.AnomalyDetection),
		zap.Duration("max_startup_delay", stdConfig.MaxStartupDelay),
	)

	// 创建并启动标准监控器
	stdMonitor := monitoring.NewProcessMonitor(stdConfig)
	if err := stdMonitor.Start(ctx); err != nil {
		log.Fatal("启动进程监控失败", zap.Error(err))
	}

	// 模拟异常进程
	go simulateAnomalyProcess(log)

	// 启动事件处理协程
	go handleEvents(stdMonitor, log)

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Info("时间异常检测测试已启动，按 Ctrl+C 退出")

	// 等待信号
	<-sigChan
	log.Info("收到退出信号，正在停止...")

	// 停止监控
	cancel()
	if err := stdMonitor.Stop(); err != nil {
		log.Error("停止监控失败", zap.Error(err))
	}

	log.Info("监控已停止")
}

func handleEvents(monitor *monitoring.ProcessMonitor, log logger.Logger) {
	eventChan := monitor.GetEventChannel()

	for event := range eventChan {
		// 基本信息
		fields := []zap.Field{
			zap.String("type", event.Type),
			zap.Int("pid", event.PID),
			zap.Int("ppid", event.PPID),
			zap.String("name", event.Name),
			zap.String("cmdline", truncateString(event.Cmdline, 50)),
			zap.Time("start_time", event.StartTime),
			zap.String("formatted_time", event.FormattedTime),
		}

		// 如果存在时间异常，添加异常信息
		if event.TimeAnomaly != nil {
			fields = append(fields,
				zap.String("anomaly", event.TimeAnomaly.Description),
				zap.String("time_diff", event.TimeAnomaly.TimeDiff),
				zap.Time("system_time", event.TimeAnomaly.SystemTime),
			)
			log.Warn("进程事件(时间异常)", fields...)
		} else {
			log.Info("进程事件", fields...)
		}
	}
}

// 模拟异常进程
func simulateAnomalyProcess(log logger.Logger) {
	// 等待几秒钟，让监控器先完成初始化
	time.Sleep(5 * time.Second)

	log.Info("开始模拟异常进程")

	// 1. 创建一个普通进程
	cmd := executeCommand("sleep 60")
	if cmd != nil {
		log.Info("创建普通进程", 
			zap.Int("pid", cmd.Process.Pid),
			zap.String("cmd", "sleep 60"))
	}

	// 等待监控器检测到第一个进程
	time.Sleep(3 * time.Second)

	// 2. 创建旧进程（启动后很久才被检测到）
	// 注：这个是通过创建进程后等待足够长时间来模拟的
	// 真实情况下可能需要通过修改/proc中的stat文件或使用ptrace等方式
	cmd = executeCommand("sleep 30")
	if cmd != nil {
		log.Info("创建旧进程(延迟检测)", 
			zap.Int("pid", cmd.Process.Pid),
			zap.String("cmd", "sleep 30"))

		// 故意等待一段时间再退出，以便在MaxStartupDelay内被检测到
		// 这种情况下，进程本身可能被监控到，但启动时间已经超过了我们设置的MaxStartupDelay
	}
}

func executeCommand(command string) *exec.Cmd {
	cmd := exec.Command("sh", "-c", command)
	err := cmd.Start()
	if err != nil {
		fmt.Printf("执行命令失败: %v\n", err)
		return nil
	}
	return cmd
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
} 