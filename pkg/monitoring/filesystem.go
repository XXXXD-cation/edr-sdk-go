package monitoring

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/XXXXD-cation/edr-sdk-go/internal/logger"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// FileEvent 文件系统事件
type FileEvent struct {
	Type      string    `json:"type"`       // create, write, remove, rename, chmod
	Path      string    `json:"path"`       // 文件路径
	OldPath   string    `json:"old_path"`   // 重命名事件的原路径
	Timestamp time.Time `json:"timestamp"`  // 事件时间戳
	Size      int64     `json:"size"`       // 文件大小
	IsDir     bool      `json:"is_dir"`     // 是否为目录
	UID       int       `json:"uid"`        // 用户ID
	GID       int       `json:"gid"`        // 组ID
	Mode      os.FileMode `json:"mode"`     // 文件权限
}

// FilesystemMonitorConfig 文件系统监控配置
type FilesystemMonitorConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	WatchPaths    []string      `mapstructure:"watch_paths"`    // 监控的路径列表
	RecursiveWatch bool         `mapstructure:"recursive_watch"` // 是否递归监控子目录
	ExcludePaths  []string      `mapstructure:"exclude_paths"`  // 排除的路径列表
	IncludeExt    []string      `mapstructure:"include_ext"`    // 包含的文件扩展名
	ExcludeExt    []string      `mapstructure:"exclude_ext"`    // 排除的文件扩展名
	BufferSize    int           `mapstructure:"buffer_size"`    // 事件缓冲区大小
	HashAlgorithm string        `mapstructure:"hash_algorithm"` // 文件哈希算法 (md5, sha1, sha256)
	CalculateHash bool          `mapstructure:"calculate_hash"` // 是否计算文件哈希
	MaxFileSize   int64         `mapstructure:"max_file_size"`  // 计算哈希的最大文件大小
}

// FilesystemMonitor 文件系统监控器
type FilesystemMonitor struct {
	config      FilesystemMonitorConfig
	logger      logger.Logger
	watcher     *fsnotify.Watcher
	eventChan   chan FileEvent
	stopChan    chan struct{}
	watchedDirs map[string]bool
	mu          sync.RWMutex
	running     bool
	wg          sync.WaitGroup
	renames     map[string]string // 跟踪重命名事件
	renamesMu   sync.Mutex        // 重命名映射的互斥锁
}

// NewFilesystemMonitor 创建新的文件系统监控器
func NewFilesystemMonitor(config FilesystemMonitorConfig) *FilesystemMonitor {
	// 设置默认值
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 10 * 1024 * 1024 // 默认10MB
	}
	if config.HashAlgorithm == "" {
		config.HashAlgorithm = "sha256"
	}

	return &FilesystemMonitor{
		config:      config,
		logger:      logger.Named("filesystem-monitor"),
		watchedDirs: make(map[string]bool),
		eventChan:   make(chan FileEvent, config.BufferSize),
		stopChan:    make(chan struct{}),
		renames:     make(map[string]string),
	}
}

// Start 启动文件系统监控
func (fm *FilesystemMonitor) Start(ctx context.Context) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.running {
		return fmt.Errorf("文件系统监控器已经在运行")
	}

	if !fm.config.Enabled {
		fm.logger.Info("文件系统监控已禁用")
		return nil
	}

	// 初始化fsnotify watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("创建文件系统监控器失败: %v", err)
	}
	fm.watcher = watcher

	// 添加监控路径
	if err := fm.addWatchPaths(); err != nil {
		fm.watcher.Close()
		return fmt.Errorf("添加监控路径失败: %v", err)
	}

	fm.running = true
	fm.logger.Info("启动文件系统监控器",
		zap.Strings("watch_paths", fm.config.WatchPaths),
		zap.Bool("recursive", fm.config.RecursiveWatch),
		zap.Int("buffer_size", fm.config.BufferSize),
	)

	// 启动监控协程
	fm.wg.Add(1)
	go fm.monitorLoop(ctx)

	return nil
}

// Stop 停止文件系统监控
func (fm *FilesystemMonitor) Stop() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if !fm.running {
		return nil
	}

	fm.logger.Info("停止文件系统监控器")
	fm.running = false
	close(fm.stopChan)
	fm.wg.Wait()

	if fm.watcher != nil {
		fm.watcher.Close()
	}

	close(fm.eventChan)
	return nil
}

// GetEventChannel 获取事件通道
func (fm *FilesystemMonitor) GetEventChannel() <-chan FileEvent {
	return fm.eventChan
}

// monitorLoop 监控循环
func (fm *FilesystemMonitor) monitorLoop(ctx context.Context) {
	defer fm.wg.Done()
	defer fm.logger.Info("文件系统监控循环退出")

	for {
		select {
		case <-ctx.Done():
			fm.logger.Info("监控循环收到上下文取消信号")
			return
		case <-fm.stopChan:
			fm.logger.Info("监控循环收到停止信号")
			return
		case event, ok := <-fm.watcher.Events:
			if !ok {
				fm.logger.Warn("监控事件通道已关闭")
				return
			}
			fm.handleFsEvent(event)
		case err, ok := <-fm.watcher.Errors:
			if !ok {
				fm.logger.Warn("监控错误通道已关闭")
				return
			}
			fm.logger.Error("文件系统监控错误", zap.Error(err))
		}
	}
}

// handleFsEvent 处理文件系统事件
func (fm *FilesystemMonitor) handleFsEvent(event fsnotify.Event) {
	// 检查是否应该忽略该事件
	if fm.shouldIgnore(event.Name) {
		return
	}

	// 处理事件类型
	var eventType string
	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		eventType = "create"
		// 如果是目录，并且启用了递归监控，则添加新目录到监控
		if fm.config.RecursiveWatch {
			fi, err := os.Stat(event.Name)
			if err == nil && fi.IsDir() {
				fm.addWatchDir(event.Name)
			}
		}
	case event.Op&fsnotify.Write == fsnotify.Write:
		eventType = "write"
	case event.Op&fsnotify.Remove == fsnotify.Remove:
		eventType = "remove"
		// 如果是监控的目录被删除，从监控列表中移除
		fm.mu.Lock()
		delete(fm.watchedDirs, event.Name)
		fm.mu.Unlock()
	case event.Op&fsnotify.Rename == fsnotify.Rename:
		eventType = "rename"
		// 处理重命名事件
		fm.handleRename(event.Name)
	case event.Op&fsnotify.Chmod == fsnotify.Chmod:
		eventType = "chmod"
	}

	// 创建文件事件
	fileEvent := FileEvent{
		Type:      eventType,
		Path:      event.Name,
		Timestamp: time.Now(),
	}

	// 获取文件信息（对于存在的文件）
	if eventType != "remove" {
		if fi, err := os.Stat(event.Name); err == nil {
			fileEvent.IsDir = fi.IsDir()
			fileEvent.Size = fi.Size()
			fileEvent.Mode = fi.Mode()

			// 获取所有者信息
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
				fileEvent.UID = int(stat.Uid)
				fileEvent.GID = int(stat.Gid)
			}
		}
	}

	// 发送事件
	fm.sendEvent(fileEvent)
}

// handleRename 处理重命名事件
func (fm *FilesystemMonitor) handleRename(path string) {
	fm.renamesMu.Lock()
	defer fm.renamesMu.Unlock()

	// fsnotify不直接提供重命名的原路径和新路径
	// 需要通过两个事件来推断：一个RENAME事件和一个CREATE事件
	// 这里使用临时存储记录重命名事件
	fm.renames[path] = path
}

// addWatchPaths 添加监控路径
func (fm *FilesystemMonitor) addWatchPaths() error {
	for _, path := range fm.config.WatchPaths {
		// 检查路径是否存在
		fi, err := os.Stat(path)
		if err != nil {
			fm.logger.Warn("监控路径不存在或无法访问",
				zap.String("path", path),
				zap.Error(err))
			continue
		}

		if !fi.IsDir() {
			// 单文件监控
			if err := fm.watcher.Add(path); err != nil {
				fm.logger.Error("添加文件监控失败",
					zap.String("path", path),
					zap.Error(err))
				continue
			}
			fm.logger.Debug("添加文件监控", zap.String("path", path))
			continue
		}

		// 目录监控
		if fm.config.RecursiveWatch {
			// 递归添加所有子目录
			if err := filepath.Walk(path, func(walkPath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() && !fm.shouldIgnore(walkPath) {
					return fm.addWatchDir(walkPath)
				}
				return nil
			}); err != nil {
				fm.logger.Error("递归添加目录监控失败",
					zap.String("path", path),
					zap.Error(err))
			}
		} else {
			// 仅监控顶级目录
			if err := fm.addWatchDir(path); err != nil {
				fm.logger.Error("添加目录监控失败",
					zap.String("path", path),
					zap.Error(err))
			}
		}
	}

	return nil
}

// addWatchDir 添加目录监控
func (fm *FilesystemMonitor) addWatchDir(dir string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// 检查是否已经在监控
	if _, exists := fm.watchedDirs[dir]; exists {
		return nil
	}

	if err := fm.watcher.Add(dir); err != nil {
		return err
	}

	fm.watchedDirs[dir] = true
	fm.logger.Debug("添加目录监控", zap.String("dir", dir))
	return nil
}

// shouldIgnore 检查是否应该忽略此路径
func (fm *FilesystemMonitor) shouldIgnore(path string) bool {
	// 检查排除路径
	for _, excl := range fm.config.ExcludePaths {
		if strings.HasPrefix(path, excl) {
			return true
		}
		
		matched, _ := filepath.Match(excl, path)
		if matched {
			return true
		}
	}

	// 检查文件扩展名
	if len(fm.config.IncludeExt) > 0 || len(fm.config.ExcludeExt) > 0 {
		ext := strings.ToLower(filepath.Ext(path))
		
		// 如果有包含列表，检查文件是否在包含列表中
		if len(fm.config.IncludeExt) > 0 {
			included := false
			for _, incExt := range fm.config.IncludeExt {
				if "."+strings.ToLower(strings.TrimPrefix(incExt, ".")) == ext {
					included = true
					break
				}
			}
			if !included {
				return true
			}
		}

		// 检查排除列表
		for _, excExt := range fm.config.ExcludeExt {
			if "."+strings.ToLower(strings.TrimPrefix(excExt, ".")) == ext {
				return true
			}
		}
	}

	return false
}

// sendEvent 发送文件事件
func (fm *FilesystemMonitor) sendEvent(event FileEvent) {
	select {
	case fm.eventChan <- event:
		fm.logger.Debug("发送文件事件",
			zap.String("type", event.Type),
			zap.String("path", event.Path),
			zap.Bool("is_dir", event.IsDir),
			zap.Int64("size", event.Size))
	default:
		fm.logger.Warn("事件通道已满，丢弃事件",
			zap.String("type", event.Type),
			zap.String("path", event.Path))
	}
} 