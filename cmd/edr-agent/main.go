package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/XXXXD-cation/edr-sdk-go/internal/config"
	"github.com/XXXXD-cation/edr-sdk-go/internal/logger"
	"github.com/XXXXD-cation/edr-sdk-go/pkg/monitoring"
	"go.uber.org/zap"
)

var (
	version   = "dev" // 由构建标志设置
	commit    = "none" // 由构建标志设置
	date      = "unknown" // 由构建标志设置
	showVersion = flag.Bool("version", false, "打印版本信息并退出")
	configPath  = flag.String("config", "", "配置文件路径")
)

// EDRAgent 是 EDR 代理的主结构
type EDRAgent struct {
	config            *config.Config
	logger            logger.Logger
	processMonitor    *monitoring.ProcessMonitor
	filesystemMonitor *monitoring.FilesystemMonitor
	networkMonitor    *monitoring.NetworkMonitor // 新增网络监控器
	stopOnce          sync.Once
	globalCtx         context.Context
	globalCancel      context.CancelFunc
	wg                sync.WaitGroup
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("EDR Agent Version: %s\nCommit: %s\nDate: %s\n", version, commit, date)
		return
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	lg, err := logger.New(cfg.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化日志系统失败: %v\n", err)
		os.Exit(1)
	}
	defer lg.Sync() // 确保在程序退出前刷新所有缓冲的日志

	lg.Info("EDR Agent 正在启动...",
		zap.String("version", version),
		zap.String("config_path", *configPath),
	)

	ctx, cancel := context.WithCancel(context.Background())

	agent := &EDRAgent{
		config:       cfg,
		logger:       lg,
		globalCtx:    ctx,
		globalCancel: cancel,
	}

	if err := agent.Start(); err != nil {
		lg.Fatal("启动 EDR Agent 失败", zap.Error(err))
	}

	// 处理信号以实现优雅关闭
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range signalChan {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				lg.Info("收到关闭信号，正在停止 Agent...", zap.String("signal", sig.String()))
				agent.Stop()
				return // 退出 goroutine
			case syscall.SIGHUP:
				lg.Info("收到 SIGHUP 信号，准备重新加载配置 (功能待实现)")
				// TODO: 实现配置热重载逻辑
				// newCfg, err := config.LoadConfig(*configPath)
				// if err != nil {
				// 	lg.Error("热重载配置失败", zap.Error(err))
				// } else {
				// 	agent.config = newCfg
				// 	lg.Info("配置已重新加载")
				// 	// 可能需要重启或重新配置某些模块
				// }
			}
		}
	}()

	agent.Wait()
	lg.Info("EDR Agent 已成功停止")
}

// Start 启动所有 EDR Agent 的组件
func (a *EDRAgent) Start() error {
	a.logger.Info("正在启动 EDR Agent 组件...")

	// 启动进程监控器
	if a.config.Monitoring.Process.Enabled {
		pmConfig := monitoring.ProcessMonitorConfig{
			Enabled:         a.config.Monitoring.Process.Enabled,
			Interval:        a.config.Monitoring.Process.Interval,
			BufferSize:      a.config.Monitoring.Process.BufferSize,
			Whitelist:       a.config.Monitoring.Process.Whitelist,
			Blacklist:       a.config.Monitoring.Process.Blacklist,
			TimeZone:        a.config.Monitoring.Process.TimeZone,
			TimeFormat:      a.config.Monitoring.Process.TimeFormat,
			AnomalyDetection: a.config.Monitoring.Process.AnomalyDetection,
			MaxStartupDelay: a.config.Monitoring.Process.MaxStartupDelay,
		}
		a.processMonitor = monitoring.NewProcessMonitor(pmConfig)
		if err := a.processMonitor.Start(a.globalCtx); err != nil {
			return fmt.Errorf("启动进程监控器失败: %w", err)
		}
		a.wg.Add(1)
		go a.handleProcessEvents(a.globalCtx)
		a.logger.Info("进程监控器已启动")
	} else {
		a.logger.Info("进程监控已禁用")
	}

	// 启动文件系统监控器
	if a.config.Monitoring.FileSystem.Enabled {
		fsmConfig := monitoring.FilesystemMonitorConfig{
			Enabled:             a.config.Monitoring.FileSystem.Enabled,
			WatchPaths:          a.config.Monitoring.FileSystem.WatchPaths,
			RecursiveWatch:      a.config.Monitoring.FileSystem.RecursiveWatch,
			ExcludePaths:        a.config.Monitoring.FileSystem.ExcludePaths,
			IncludeExt:          a.config.Monitoring.FileSystem.IncludeExt,
			ExcludeExt:          a.config.Monitoring.FileSystem.ExcludeExt,
			BufferSize:          a.config.Monitoring.FileSystem.BufferSize,
			HashAlgorithm:       a.config.Monitoring.FileSystem.HashAlgorithm,
			CalculateHash:       a.config.Monitoring.FileSystem.CalculateHash,
			MaxFileSize:         a.config.Monitoring.FileSystem.MaxFileSize,
			RenameMatchWindow:   a.config.Monitoring.FileSystem.RenameMatchWindow,
			RenameCleanupInterval: a.config.Monitoring.FileSystem.RenameCleanupInterval,
		}
		a.filesystemMonitor = monitoring.NewFilesystemMonitor(fsmConfig)
		if err := a.filesystemMonitor.Start(a.globalCtx); err != nil {
			// 如果文件系统监控启动失败，停止已启动的进程监控（如果存在）
			if a.processMonitor != nil {
				_ = a.processMonitor.Stop() // 忽略错误，因为我们即将返回一个更重要的错误
			}
			return fmt.Errorf("启动文件系统监控器失败: %w", err)
		}
		a.wg.Add(1)
		go a.handleFilesystemEvents(a.globalCtx)
		a.logger.Info("文件系统监控器已启动")
	} else {
		a.logger.Info("文件系统监控已禁用")
	}

	// 启动网络监控器 (新增)
	if a.config.Monitoring.Network.Enabled {
		nmConfig := monitoring.NetworkMonitorConfig{
			Enabled:             a.config.Monitoring.Network.Enabled,
			BufferSize:          a.config.Monitoring.Network.BufferSize,
			PerfEventBufferPages: a.config.Monitoring.Network.PerfEventBufferPages,
		}
		a.networkMonitor = monitoring.NewNetworkMonitor(nmConfig)
		if err := a.networkMonitor.Start(a.globalCtx); err != nil {
			if a.processMonitor != nil {
				_ = a.processMonitor.Stop()
			}
			if a.filesystemMonitor != nil {
				_ = a.filesystemMonitor.Stop()
			}
			return fmt.Errorf("启动网络监控器失败: %w", err)
		}
		a.wg.Add(1)
		go a.handleNetworkEvents(a.globalCtx) // 新的事件处理 goroutine
		a.logger.Info("网络监控器已启动")
	} else {
		a.logger.Info("网络监控已禁用")
	}

	return nil
}

// Stop 停止所有 EDR Agent 的组件
func (a *EDRAgent) Stop() {
	a.stopOnce.Do(func() {
		a.logger.Info("EDR Agent 正在停止...")
		a.globalCancel() // 发出全局停止信号

		var lastErr error

		// 停止网络监控器
		if a.networkMonitor != nil {
			a.logger.Debug("正在停止网络监控器...")
			if err := a.networkMonitor.Stop(); err != nil {
				a.logger.Error("停止网络监控器失败", zap.Error(err))
				lastErr = err // 记录最后一个错误
			}
			a.logger.Info("网络监控器已停止")
		}

		// 停止文件系统监控器
		if a.filesystemMonitor != nil {
			a.logger.Debug("正在停止文件系统监控器...")
			if err := a.filesystemMonitor.Stop(); err != nil {
				a.logger.Error("停止文件系统监控器失败", zap.Error(err))
				lastErr = err
			}
			a.logger.Info("文件系统监控器已停止")
		}

		// 停止进程监控器
		if a.processMonitor != nil {
			a.logger.Debug("正在停止进程监控器...")
			if err := a.processMonitor.Stop(); err != nil {
				a.logger.Error("停止进程监控器失败", zap.Error(err))
				lastErr = err
			}
			a.logger.Info("进程监控器已停止")
		}

		if lastErr != nil {
			a.logger.Warn("在停止过程中至少发生一个错误", zap.Error(lastErr))
		}
	})
}

// Wait 等待所有 Agent 的 goroutine 完成
func (a *EDRAgent) Wait() {
	a.wg.Wait()
}

// handleProcessEvents 处理进程监控事件
func (a *EDRAgent) handleProcessEvents(ctx context.Context) {
	defer a.wg.Done()
	if a.processMonitor == nil {
		return
	}
	processEventChan := a.processMonitor.GetEventChannel()
	a.logger.Info("开始监听进程事件...")
	for {
		select {
		case event, ok := <-processEventChan:
			if !ok {
				a.logger.Info("进程事件通道已关闭")
				return
			}
			a.processProcessEvent(event)
		case <-ctx.Done():
			a.logger.Info("进程事件处理 goroutine 收到停止信号")
			return
		}
	}
}

// processProcessEvent 处理单个进程事件 (当前仅记录日志)
func (a *EDRAgent) processProcessEvent(event monitoring.ProcessEvent) {
	a.logger.Info("收到进程事件",
		zap.String("type", event.Type),
		zap.Int("pid", event.PID),
		zap.String("name", event.Name),
		zap.String("cmdline", event.Cmdline),
		zap.Time("timestamp", event.Timestamp),
		zap.String("start_time", event.FormattedTime),
	)
	if event.TimeAnomaly != nil {
		a.logger.Warn("检测到进程启动时间异常",
			zap.Int("pid", event.TimeAnomaly.PID),
			zap.String("name", event.TimeAnomaly.Name),
			zap.Time("process_start_time", event.TimeAnomaly.StartTime),
			zap.Time("system_time_at_check", event.TimeAnomaly.SystemTime),
			zap.String("difference", event.TimeAnomaly.TimeDiff),
			zap.String("description", event.TimeAnomaly.Description),
		)
	}
}

// handleFilesystemEvents 处理文件系统监控事件
func (a *EDRAgent) handleFilesystemEvents(ctx context.Context) {
	defer a.wg.Done()
	if a.filesystemMonitor == nil {
		return
	}
	fsEventChan := a.filesystemMonitor.GetEventChannel()
	a.logger.Info("开始监听文件系统事件...")
	for {
		select {
		case event, ok := <-fsEventChan:
			if !ok {
				a.logger.Info("文件系统事件通道已关闭")
				return
			}
			a.processFilesystemEvent(event)
		case <-ctx.Done():
			a.logger.Info("文件系统事件处理 goroutine 收到停止信号")
			return
		}
	}
}

// processFilesystemEvent 处理单个文件系统事件 (当前仅记录日志)
func (a *EDRAgent) processFilesystemEvent(event monitoring.FileEvent) {
	fields := []zap.Field{
		zap.String("type", event.Type),
		zap.String("path", event.Path),
		zap.Time("timestamp", event.Timestamp),
	}
	if event.OldPath != "" {
		fields = append(fields, zap.String("old_path", event.OldPath))
	}
	if event.IsDir {
		fields = append(fields, zap.Bool("is_dir", event.IsDir))
	}
	if event.Size > 0 {
		fields = append(fields, zap.Int64("size", event.Size))
	}
	if event.Hash != "" {
		fields = append(fields, zap.String("hash", event.Hash))
	}
	if event.Error != nil {
		fields = append(fields, zap.Error(event.Error))
	}
	a.logger.Info("收到文件系统事件", fields...)
}

// handleNetworkEvents 处理网络监控事件 (新增)
func (a *EDRAgent) handleNetworkEvents(ctx context.Context) {
	defer a.wg.Done()
	if a.networkMonitor == nil {
		return
	}
	netEventChan := a.networkMonitor.GetEventChannel()
	a.logger.Info("开始监听网络事件...")
	for {
		select {
		case event, ok := <-netEventChan:
			if !ok {
				a.logger.Info("网络事件通道已关闭")
				return
			}
			a.processNetworkEvent(event)
		case <-ctx.Done():
			a.logger.Info("网络事件处理 goroutine 收到停止信号")
			return
		}
	}
}

// processNetworkEvent 处理单个网络事件 (当前仅记录日志)
func (a *EDRAgent) processNetworkEvent(event monitoring.NetworkEvent) {
	fields := []zap.Field{
		zap.String("type", string(event.Type)),
		zap.Time("timestamp", event.Timestamp),
		zap.Uint32("pid", event.PID),
		zap.String("comm", event.Comm),
		zap.String("protocol", event.Protocol),
		zap.String("family", event.Family),
		zap.String("src_ip", event.SrcIP),
		zap.Uint16("src_port", event.SrcPort),
		zap.String("dest_ip", event.DestIP),
		zap.Uint16("dest_port", event.DestPort),
		zap.Uint64("socket_cookie", event.SocketCookie),
	}
	if event.NetNS != 0 {
		fields = append(fields, zap.Uint32("netns", event.NetNS))
	}
	if event.Error != "" {
		fields = append(fields, zap.String("error", event.Error))
	}
	a.logger.Info("收到网络事件", fields...)
} 