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
		Level:  "debug",
		Format: "console",
		Output: "stdout",
	}

	if err := logger.InitGlobalLogger(logConfig); err != nil {
		log.Fatalf("初始化日志失败: %v", err)
	}

	log := logger.GetLogger()
	log.Info("启动文件系统监控示例")

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 配置文件系统监控器
	config := monitoring.FilesystemMonitorConfig{
		Enabled:        true,
		WatchPaths:     []string{"/tmp/edr-test", "/home/ccnochch/edr-test"},
		RecursiveWatch: true,
		ExcludePaths:   []string{"/tmp/edr-test/exclude"},
		IncludeExt:     []string{".txt", ".log", ".conf", ".json", ".yaml", ".go"},
		ExcludeExt:     []string{".tmp", ".swp"},
		BufferSize:     1000,
		CalculateHash:  true,
		HashAlgorithm:  "sha256",
		MaxFileSize:    5 * 1024 * 1024, // 5MB
	}

	// 确保测试目录存在
	ensureTestDirs(config.WatchPaths)

	// 创建并启动文件系统监控器
	fsMonitor := monitoring.NewFilesystemMonitor(config)
	if err := fsMonitor.Start(ctx); err != nil {
		log.Fatal("启动文件系统监控失败", zap.Error(err))
	}

	// 启动事件处理协程
	go handleEvents(fsMonitor, log)

	// 创建一些测试文件
	go generateTestFiles(log)

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Info("文件系统监控已启动，按 Ctrl+C 退出")

	// 等待信号
	<-sigChan
	log.Info("收到退出信号，正在停止...")

	// 停止监控
	cancel()
	if err := fsMonitor.Stop(); err != nil {
		log.Error("停止监控失败", zap.Error(err))
	}

	log.Info("监控已停止")
}

// 处理文件系统事件
func handleEvents(monitor *monitoring.FilesystemMonitor, log logger.Logger) {
	eventChan := monitor.GetEventChannel()

	for event := range eventChan {
		// 基本信息
		fields := []zap.Field{
			zap.String("type", event.Type),
			zap.String("path", event.Path),
			zap.Bool("is_dir", event.IsDir),
			zap.Time("timestamp", event.Timestamp),
		}

		// 额外信息
		if event.Size > 0 {
			fields = append(fields, zap.Int64("size", event.Size))
		}
		if event.OldPath != "" {
			fields = append(fields, zap.String("old_path", event.OldPath))
		}

		// 输出事件
		switch event.Type {
		case "create":
			log.Info("文件创建", fields...)
		case "write":
			log.Info("文件修改", fields...)
		case "remove":
			log.Info("文件删除", fields...)
		case "rename":
			log.Info("文件重命名", fields...)
		case "chmod":
			log.Info("文件权限变更", fields...)
		default:
			log.Info("文件事件", fields...)
		}
	}
}

// 确保测试目录存在
func ensureTestDirs(dirs []string) {
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			os.MkdirAll(dir, 0755)
			os.MkdirAll(dir+"/subdir", 0755)
		}
	}
}

// 生成测试文件
func generateTestFiles(log logger.Logger) {
	// 等待监控器启动
	time.Sleep(2 * time.Second)

	testDir := "/tmp/edr-test"

	// 创建测试文件
	log.Info("创建测试文件")
	writeFile(testDir+"/test1.txt", "Hello, EDR SDK!")
	writeFile(testDir+"/test2.log", "This is a log file")
	writeFile(testDir+"/config.json", `{"key": "value"}`)
	writeFile(testDir+"/subdir/nested.txt", "Nested file content")

	// 等待事件处理
	time.Sleep(1 * time.Second)

	// 修改文件
	log.Info("修改测试文件")
	writeFile(testDir+"/test1.txt", "Updated content")
	
	// 等待事件处理
	time.Sleep(1 * time.Second)

	// 重命名文件
	log.Info("重命名测试文件")
	os.Rename(testDir+"/test2.log", testDir+"/test2.log.old")

	// 等待事件处理
	time.Sleep(1 * time.Second)

	// 更改权限
	log.Info("更改文件权限")
	os.Chmod(testDir+"/test1.txt", 0644)

	// 等待事件处理
	time.Sleep(1 * time.Second)

	// 创建排除的文件类型
	log.Info("创建应被排除的文件")
	writeFile(testDir+"/temp.tmp", "Temporary file")
	writeFile(testDir+"/editor.swp", "Swap file")

	// 创建排除目录
	if _, err := os.Stat(testDir + "/exclude"); os.IsNotExist(err) {
		os.MkdirAll(testDir+"/exclude", 0755)
	}
	writeFile(testDir+"/exclude/excluded.txt", "This should be excluded")

	// 等待事件处理
	time.Sleep(1 * time.Second)

	// 删除文件
	log.Info("删除测试文件")
	os.Remove(testDir + "/test1.txt")
}

// 写入文件
func writeFile(path string, content string) {
	os.WriteFile(path, []byte(content), 0644)
} 