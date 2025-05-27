package monitoring

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io/ioutil"
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

// FileEvent 文件事件结构体定义
type FileEvent struct {
	Type      string    `json:"type"`       // 事件类型：create, write, remove, rename, chmod
	Path      string    `json:"path"`       // 文件或目录的路径
	OldPath   string    `json:"old_path,omitempty"`   // 如果是rename事件，表示重命名之前的路径
	Timestamp time.Time `json:"timestamp"`  // 事件发生的时间戳
	Size      int64     `json:"size"`       // 文件大小（字节）
	IsDir     bool      `json:"is_dir"`     // 是否为目录
	UID       int       `json:"uid"`        // 文件所有者的用户ID
	GID       int       `json:"gid"`        // 文件所有者的组ID
	Mode      os.FileMode `json:"mode"`     // 文件权限模式 (例如：0644)
	Hash      string    `json:"hash,omitempty"` // 文件的哈希值 (如果计算了)
	Error     error     `json:"error,omitempty"` // 事件相关的错误信息（如果有）
}

// FilesystemMonitorConfig 文件系统监控器的配置选项
type FilesystemMonitorConfig struct {
	Enabled             bool          `mapstructure:"enabled"`               // 是否启用监控器
	WatchPaths          []string      `mapstructure:"watch_paths"`           // 需要监控的初始路径列表
	RecursiveWatch      bool          `mapstructure:"recursive_watch"`        // 是否递归监控子目录
	ExcludePaths        []string      `mapstructure:"exclude_paths"`         // 需要排除的路径列表 (支持glob模式匹配)
	IncludeExt          []string      `mapstructure:"include_ext"`           // 只监控包含这些扩展名的文件 (例如: [".log", ".txt"])
	ExcludeExt          []string      `mapstructure:"exclude_ext"`           // 排除这些扩展名的文件 (例如: [".tmp", ".bak"])
	BufferSize          int           `mapstructure:"buffer_size"`           // 内部事件通道的缓冲区大小
	HashAlgorithm       string        `mapstructure:"hash_algorithm"`        // 计算文件哈希时使用的算法 (md5, sha1, sha256)
	CalculateHash       bool          `mapstructure:"calculate_hash"`        // 是否计算文件哈希值
	MaxFileSize         int64         `mapstructure:"max_file_size"`         // 计算哈希值的最大文件大小 (字节)，超过此大小不计算哈希
	RenameMatchWindow   time.Duration `mapstructure:"rename_match_window"`  // 重命名事件的匹配窗口：在此时间内发生的RENAME和CREATE事件会被视为一个重命名操作
	RenameCleanupInterval time.Duration `mapstructure:"rename_cleanup_interval"` // 定期清理悬挂的RENAME事件（未配对的）的间隔
}

// FilesystemMonitor 文件系统监控器结构体
type FilesystemMonitor struct {
	config             FilesystemMonitorConfig // 监控器配置
	logger             logger.Logger         // 日志记录器
	watcher            *fsnotify.Watcher     // fsnotify的watcher实例
	eventChan          chan FileEvent        // 文件事件输出通道
	stopChan           chan struct{}         // 用于通知goroutine停止的通道
	watchedDirs        map[string]bool       // 记录当前正在被fsnotify监控的目录路径 (true表示目录, false表示文件本身被监控)
	mu                 sync.RWMutex          // 用于保护running状态和watchedDirs的读写锁
	running            bool                  // 监控器是否正在运行
	wg                 sync.WaitGroup        // 用于等待所有goroutine退出的WaitGroup
	pendingRenamesFrom map[string]time.Time // 暂存RENAME事件的旧路径及其时间戳，用于匹配后续的CREATE事件
	pendingRenamesMu   sync.Mutex            // 用于保护pendingRenamesFrom的互斥锁
}

// NewFilesystemMonitor 创建并返回一个新的文件系统监控器实例
func NewFilesystemMonitor(config FilesystemMonitorConfig) *FilesystemMonitor {
	// 为配置设置默认值
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 10 * 1024 * 1024 // 默认10MB
	}
	if config.HashAlgorithm == "" {
		config.HashAlgorithm = "sha256" // 默认SHA256
	}
	if config.RenameMatchWindow == 0 {
		config.RenameMatchWindow = 2 * time.Second // 默认2秒
	}
	if config.RenameCleanupInterval == 0 {
		config.RenameCleanupInterval = 5 * time.Second // 默认5秒
	}

	return &FilesystemMonitor{
		config:             config,
		logger:             logger.Named("filesystem-monitor"),
		eventChan:          make(chan FileEvent, config.BufferSize),
		stopChan:           make(chan struct{}),
		watchedDirs:        make(map[string]bool),
		pendingRenamesFrom: make(map[string]time.Time),
	}
}

// Start 启动文件系统监控器
// 它会初始化fsnotify watcher，添加监控路径，并启动监控goroutine和重命名清理goroutine。
func (fm *FilesystemMonitor) Start(ctx context.Context) error {
	fm.mu.Lock()

	if fm.running {
		fm.mu.Unlock()
		return fmt.Errorf("文件系统监控器已经在运行")
	}

	if !fm.config.Enabled {
		fm.mu.Unlock()
		fm.logger.Info("文件系统监控已禁用，将不会启动")
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fm.mu.Unlock()
		return fmt.Errorf("创建fsnotify watcher失败: %v", err)
	}
	fm.watcher = watcher
	fm.running = true
	fm.mu.Unlock()

	if err := fm.addWatchPaths(); err != nil {
		fm.mu.Lock()
		fm.watcher.Close() // 如果添加路径失败，需要关闭已创建的watcher
		fm.running = false
		fm.mu.Unlock()
		return fmt.Errorf("添加监控路径到watcher失败: %v", err)
	}

	fm.logger.Info("文件系统监控器已启动",
		zap.Strings("监控路径", fm.config.WatchPaths),
		zap.Bool("递归监控", fm.config.RecursiveWatch),
		zap.Int("事件缓冲区大小", fm.config.BufferSize),
	)

	fm.wg.Add(1) // 为monitorLoop goroutine计数
	go fm.monitorLoop(ctx)
	
	fm.wg.Add(1) // 为renameCleanupLoop goroutine计数
	go fm.renameCleanupLoop(ctx)

	return nil
}

// Stop 停止文件系统监控器
// 它会关闭stopChan以通知goroutine停止，关闭fsnotify watcher，并等待所有goroutine退出。
func (fm *FilesystemMonitor) Stop() error {
	fm.mu.Lock()
	
	if !fm.running {
		fm.mu.Unlock()
		fm.logger.Info("文件系统监控器未运行，无需停止")
		return nil
	}

	fm.logger.Info("正在停止文件系统监控器...")
	fm.running = false      // 设置运行状态为false
	close(fm.stopChan)      // 关闭停止通道，通知goroutines退出

	if fm.watcher != nil {
		fm.watcher.Close()  // 关闭fsnotify watcher
	}
	fm.mu.Unlock() // 在等待WaitGroup之前解锁，以避免潜在的死锁（例如，如果goroutine在退出时尝试获取锁进行日志记录）

	fm.wg.Wait() // 等待所有goroutine完成
	
	// fm.mu.Lock() // 如果需要在所有goroutine停止后进一步清理（例如关闭eventChan），则重新获取锁
	// close(fm.eventChan) // 考虑是否以及何时关闭事件通道。通常由读取方负责判断通道关闭。
	// fm.mu.Unlock()

	fm.logger.Info("文件系统监控器已成功停止")
	return nil
}

// GetEventChannel 返回文件事件的只读通道，外部可以通过此通道接收监控到的事件。
func (fm *FilesystemMonitor) GetEventChannel() <-chan FileEvent {
	return fm.eventChan
}

// monitorLoop 是主监控循环的goroutine
// 它监听fsnotify的事件和错误，以及停止信号。
func (fm *FilesystemMonitor) monitorLoop(ctx context.Context) {
	defer fm.wg.Done() // 确保WaitGroup在goroutine退出时递减
	defer fm.logger.Info("文件系统监控主循环已退出")

	for {
		select {
		case <-ctx.Done(): // 如果外部上下文被取消
			fm.logger.Info("监控主循环因上下文取消而退出")
			return
		case <-fm.stopChan: // 如果收到停止信号
			fm.logger.Info("监控主循环因收到停止信号而退出")
			return
		case event, ok := <-fm.watcher.Events: // 收到fsnotify事件
			if !ok {
				fm.logger.Warn("fsnotify事件通道已关闭，监控主循环退出")
				return
			}
			fm.handleFsEvent(event) // 处理事件
		case err, ok := <-fm.watcher.Errors: // 收到fsnotify错误
			if !ok {
				fm.logger.Warn("fsnotify错误通道已关闭，监控主循环退出")
				return
			}
			fm.logger.Error("文件系统监控器遇到错误", zap.Error(err))
		}
	}
}

// renameCleanupLoop 是定期清理未配对的RENAME事件的goroutine。
// fsnotify对于跨目录的移动可能会产生一个RENAME事件（源路径）和一个CREATE事件（目标路径）。
// 如果只收到了RENAME事件而没有后续的CREATE事件（可能因为目标不在监控范围内，或事件丢失），
// 这个goroutine会确保这些悬挂的RENAME事件最终被作为REMOVE事件处理掉。
func (fm *FilesystemMonitor) renameCleanupLoop(ctx context.Context) {
	defer fm.wg.Done() // 确保WaitGroup在goroutine退出时递减
	defer fm.logger.Info("重命名事件清理循环已退出")

	ticker := time.NewTicker(fm.config.RenameCleanupInterval) // 定时器，按配置的间隔触发清理
	defer ticker.Stop() // 停止定时器，释放资源

	for {
		select {
		case <-ctx.Done(): // 如果外部上下文被取消
			fm.logger.Info("重命名清理循环因上下文取消而退出")
			return
		case <-fm.stopChan: // 如果收到停止信号
			fm.logger.Info("重命名清理循环因收到停止信号而退出")
			return
		case <-ticker.C: // 定时器触发
			fm.cleanupPendingRenames()
		}
	}
}

// cleanupPendingRenames 清理过期的、未配对的RENAME事件。
// 如果一个RENAME事件（源路径）在一段时间内没有匹配到相应的CREATE事件（目标路径），
// 就认为原始文件已被移出监控范围或被删除，因此将其作为REMOVE事件发送。
func (fm *FilesystemMonitor) cleanupPendingRenames() {
	fm.pendingRenamesMu.Lock() // 保护对pendingRenamesFrom的访问
	defer fm.pendingRenamesMu.Unlock()

	now := time.Now()
	// 清理阈值比匹配窗口稍长，给匹配留出足够时间，同时确保不会无限期等待
	cleanupThreshold := fm.config.RenameMatchWindow + (fm.config.RenameCleanupInterval / 2) 
	if cleanupThreshold < 3*time.Second { // 确保一个最小合理的清理阈值，例如3秒
		cleanupThreshold = 3 * time.Second
	}


	for oldPath, renameTime := range fm.pendingRenamesFrom {
		if now.Sub(renameTime) > cleanupThreshold { // 如果事件已过期
			fm.logger.Debug("检测到过期的RENAME事件（源路径），将作为REMOVE事件处理", zap.String("过期路径", oldPath))
			
			event := FileEvent{
				Type:      "remove", // 可以考虑更具体的类型，如 "rename_out_of_watch"
				Path:      oldPath,
				Timestamp: now, // 使用当前时间作为事件时间戳
			}
			fm.sendEvent(event) // 发送REMOVE事件
			delete(fm.pendingRenamesFrom, oldPath) // 从暂存map中移除
		}
	}
}


// handleFsEvent 处理来自fsnotify的原始事件，将其转换为自定义的FileEvent，并进行必要的逻辑处理（如重命名匹配）。
func (fm *FilesystemMonitor) handleFsEvent(event fsnotify.Event) {
	absPath := filepath.Clean(event.Name) // 清理并获取绝对路径

	if fm.shouldIgnore(absPath) { // 检查是否应忽略此路径的事件
		fm.logger.Debugw("忽略被排除路径的事件", "路径", absPath, "操作", event.Op.String())
		return
	}

	var finalEventType string      // 最终确定的事件类型 (create, write, remove, rename, chmod)
	var oldPathForFinalEvent string // 如果是rename事件，这里存储旧路径
	var fileInfo os.FileInfo       // 用于存储os.Stat的结果
	var skipEvent bool = false     // 标记是否应该跳过发送此事件

	// 首先处理RENAME事件（代表重命名或移动操作的源头）。
	// 这是特殊情况，需要暂存以备后续与CREATE事件配对。
	if event.Op&fsnotify.Rename == fsnotify.Rename {
		fm.logger.Debugw("原始fsnotify RENAME事件 (重命名/移动操作的源文件)", "旧路径", absPath)
		fm.pendingRenamesMu.Lock()
		fm.pendingRenamesFrom[absPath] = time.Now() // 暂存路径和当前时间
		fm.pendingRenamesMu.Unlock()
		// 此路径现在被视为潜在重命名/移动的"源"。
		// 我们暂时不发送事件，等待一个相应的CREATE事件来与之配对，
		// 或者等待清理goroutine在没有CREATE事件出现时处理它。
		return // 直接返回，不立即发送事件
	}

	// 对于其他类型的操作，如果不是REMOVE操作，尝试尽早获取文件信息。
	var statError error
	if !(event.Op&fsnotify.Remove == fsnotify.Remove) { // 如果最初不是REMOVE操作，则尝试Stat
		fileInfo, statError = os.Stat(absPath)
		if statError != nil {
			// 记录此错误，但这可能不是致命的（例如，文件被创建后在Stat之前立即被删除）。
			fm.logger.Debugw("对非REMOVE事件的初始Stat失败", "路径", absPath, "操作", event.Op.String(), "错误", statError)
		}
	}

	switch { // 根据fsnotify事件的操作类型进行处理
	case event.Op&fsnotify.Create == fsnotify.Create:
		fm.logger.Debugw("原始fsnotify CREATE事件", "路径", absPath)
		fm.pendingRenamesMu.Lock() // 保护对pendingRenamesFrom的访问
		var matchedOldPath string
		// 遍历暂存的RENAME事件，查找是否有匹配的源路径
		for oldPathCandidate, ts := range fm.pendingRenamesFrom {
			if time.Since(ts) < fm.config.RenameMatchWindow { // 如果在匹配窗口内
				matchedOldPath = oldPathCandidate
				delete(fm.pendingRenamesFrom, oldPathCandidate) // 从暂存map中移除已匹配的项
				fm.logger.Debugw("成功将RENAME(源)与CREATE(目标)配对", "旧路径", matchedOldPath, "新路径", absPath)
				break // 找到匹配，停止搜索
			}
		}
		fm.pendingRenamesMu.Unlock()

		if matchedOldPath != "" { // 如果找到了匹配的旧路径，则这是一个rename事件
			finalEventType = "rename"
			oldPathForFinalEvent = matchedOldPath
		} else { // 否则，这是一个普通的create事件
			finalEventType = "create"
		}
		// 如果之前获取fileInfo失败 (例如statError不为nil)，则为Create事件再次尝试获取。
		if fileInfo == nil && statError != nil { 
			fileInfo, statError = os.Stat(absPath)
			if statError != nil {
				fm.logger.Warnw("为CREATE事件路径执行Stat失败", "路径", absPath, "错误", statError)
			}
		}
		// 如果创建的是一个新目录，并且配置了递归监控，则将此新目录添加到监控列表。
		if fileInfo != nil && fileInfo.IsDir() && fm.config.RecursiveWatch && !fm.shouldIgnore(absPath) {
			if err := fm.addWatchDir(absPath); err != nil {
				fm.logger.Errorw("未能将新创建的目录添加到递归监控", "路径", absPath, "错误", err)
			}
		}

	case event.Op&fsnotify.Write == fsnotify.Write:
		fm.logger.Debugw("原始fsnotify WRITE事件", "路径", absPath)
		finalEventType = "write"

	case event.Op&fsnotify.Remove == fsnotify.Remove: // 此情况在RENAME已被处理之后。
		fm.logger.Debugw("原始fsnotify REMOVE事件", "路径", absPath)
		finalEventType = "remove"
		// 如果此路径是一个待处理的RENAME源路径，意味着它在CREATE配对之前就被移除了。
		fm.pendingRenamesMu.Lock()
		if _, isPending := fm.pendingRenamesFrom[absPath]; isPending {
			delete(fm.pendingRenamesFrom, absPath)
			fm.logger.Debugw("由于REMOVE事件，清除了待处理的RENAME(源)路径", "路径", absPath)
		}
		fm.pendingRenamesMu.Unlock()
		// 对于REMOVE事件，之前获取的fileInfo（如果在switch之前获取）可能已过时或来自删除前。
		// 通常我们不需要为已删除文件的事件本身获取最新的stat信息。
		fileInfo = nil // 将预获取的fileInfo置为nil，表示对于remove事件无效或不需要

	case event.Op&fsnotify.Chmod == fsnotify.Chmod:
		fm.logger.Debugw("原始fsnotify CHMOD事件", "路径", absPath)
		finalEventType = "chmod"

	default: // 未知或未处理的fsnotify操作
		fm.logger.Debugw("未知或未处理的fsnotify事件操作", "路径", absPath, "操作", event.Op.String())
		skipEvent = true // 标记跳过此事件
	}

	if skipEvent || finalEventType == "" { // 如果标记了跳过，或者最终事件类型为空
		if finalEventType == "" && !skipEvent { // 如果事件类型为空但没有显式标记跳过，记录警告
			fm.logger.Warnw("事件类型判断为空，跳过发送", "路径", absPath, "操作", event.Op.String())
		}
		return // 不发送事件
	}

	// 如果对于相关事件类型（create, rename, write, chmod），fileInfo仍然为nil：
	// 这可能意味着初始Stat成功了但未存储，或者初始Stat失败了，或者根本没有执行Stat（如REMOVE事件）。
	// 我们需要确保对于要发送的事件类型，fileInfo是最新的（如果可能获取到）。
	if fileInfo == nil && finalEventType != "remove" { // 对于非remove事件，如果fileInfo为空则尝试再次Stat
		var currentStatErr error
		fileInfo, currentStatErr = os.Stat(absPath) // 尝试获取当前最新的Stat信息
		if currentStatErr != nil {
			fm.logger.Warnw("获取文件Stat信息失败，将使用最少信息继续处理事件", 
				"路径", absPath, "类型", finalEventType, "错误", currentStatErr)
		}
	}

	// 创建自定义的FileEvent
	fe := FileEvent{
		Type:      finalEventType,
		Path:      absPath,
		OldPath:   oldPathForFinalEvent,
		Timestamp: time.Now(), // 使用当前时间作为事件的时间戳
	}

	if fileInfo != nil { // 如果成功获取了fileInfo (对于Stat失败的情况，fileInfo可能仍然是nil)
		fe.IsDir = fileInfo.IsDir()
		fe.Size = fileInfo.Size()
		fe.Mode = fileInfo.Mode().Perm() // 获取权限位
		if statSys, ok := fileInfo.Sys().(*syscall.Stat_t); ok { // 获取UID和GID (Linux特定)
			fe.UID = int(statSys.Uid)
			fe.GID = int(statSys.Gid)
		}
	}

	// 如果不是目录、配置了计算哈希，并且不是remove事件，则计算哈希
	if !fe.IsDir && fm.config.CalculateHash && finalEventType != "remove" {
		// 仅当文件信息有效、文件大小在限制内且大于0时才计算哈希
		if fileInfo != nil && fileInfo.Size() <= fm.config.MaxFileSize && fileInfo.Size() > 0 {
			hashStr, hashErr := fm.calculateFileHash(absPath)
			if hashErr == nil {
				fe.Hash = hashStr
			} else {
				fm.logger.Warnw("计算文件哈希失败", "路径", absPath, "错误", hashErr)
			}
		} else if fileInfo == nil && (finalEventType == "create" || finalEventType == "rename" || finalEventType == "write"){
			// 如果fileInfo为空，但事件类型是可能期望哈希的（且非remove事件），记录调试信息
			fm.logger.Debugw("由于文件信息缺失，跳过哈希计算", "路径", absPath, "类型", finalEventType)
		}
	}

	fm.sendEvent(fe) // 发送组装好的FileEvent
}

// addWatchPaths 将配置中指定的初始监控路径添加到fsnotify watcher。
// 支持递归监控子目录。
func (fm *FilesystemMonitor) addWatchPaths() error {
	for _, path := range fm.config.WatchPaths {
		absPath, err := filepath.Abs(path) // 获取绝对路径
		if err != nil {
			fm.logger.Warn("获取监控路径的绝对路径失败，跳过此路径", zap.String("原始路径", path), zap.Error(err))
			continue
		}

		fi, err := os.Stat(absPath) // 获取路径信息
		if err != nil {
			fm.logger.Warn("监控路径不存在或无法访问，跳过此路径", zap.String("路径", absPath), zap.Error(err))
			continue
		}

		if !fi.IsDir() { // 如果是文件而不是目录
			if !fm.shouldIgnore(absPath) { // 检查是否应忽略
				// 对于文件，fsnotify通常监控其父目录以捕获事件。这里直接添加文件路径，fsnotify库会处理。
				if err := fm.watcher.Add(absPath); err != nil { 
					fm.logger.Error("添加文件到fsnotify watcher失败", zap.String("文件路径", absPath), zap.Error(err))
				} else {
					fm.logger.Debug("成功添加文件监控", zap.String("文件路径", absPath))
					fm.mu.Lock()
					fm.watchedDirs[absPath] = false // false表示这是一个文件监控项
					fm.mu.Unlock()
				}
			}
			continue // 处理下一个路径
		}

		// 如果是目录
		if fm.config.RecursiveWatch { // 如果启用了递归监控
			err = filepath.Walk(absPath, func(walkPath string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					// 记录访问路径时的错误，并决定是否跳过此目录或文件
					fm.logger.Warn("递归遍历路径时访问出错", zap.String("路径", walkPath), zap.Error(walkErr))
					if info != nil && info.IsDir() {
						return filepath.SkipDir // 如果是目录且无法访问，则跳过此目录及其子目录
					}
					return nil // 否则，跳过此文件/条目，继续遍历其他部分
				}
				if info.IsDir() && !fm.shouldIgnore(walkPath) { // 如果是目录且不应被忽略
					return fm.addWatchDir(walkPath) // 添加此目录到监控
				}
				return nil // 其他情况（非目录或应忽略的目录），继续遍历
			})
			if err != nil {
				fm.logger.Error("递归添加目录监控失败", zap.String("根路径", absPath), zap.Error(err))
			}
		} else { // 如果未启用递归监控，则只监控当前目录本身
			if !fm.shouldIgnore(absPath) {
				if err := fm.addWatchDir(absPath); err != nil {
					fm.logger.Error("添加非递归目录监控失败", zap.String("路径", absPath), zap.Error(err))
				}
			}
		}
	}
	return nil
}

// addWatchDir 将单个目录添加到fsnotify watcher进行监控。
// 这是一个内部函数，主要由addWatchPaths或事件处理器（当新目录被创建时）调用。
func (fm *FilesystemMonitor) addWatchDir(dir string) error {
	absDir, err := filepath.Abs(dir) // 获取绝对路径
	if err != nil {
		fm.logger.Error("获取目录的绝对路径失败 (addWatchDir)", zap.String("原始路径", dir), zap.Error(err))
		return err
	}

	fm.mu.Lock() // 保护对watchedDirs的访问
	defer fm.mu.Unlock()

	if _, exists := fm.watchedDirs[absDir]; exists { // 如果此目录已在监控列表中
		fm.logger.Debug("目录已在监控列表中，无需重复添加", zap.String("路径", absDir))
		return nil 
	}

	if err := fm.watcher.Add(absDir); err != nil { // 尝试添加到fsnotify watcher
		// 如果错误是"no space left on device"，通常意味着达到了系统允许的最大监控数限制
		if strings.Contains(err.Error(), "no space left on device") {
			fm.logger.Warn("添加目录到fsnotify失败 (可能是已达到系统最大监控文件/目录数)", zap.String("路径", absDir), zap.Error(err))
		} else {
			fm.logger.Error("添加目录到fsnotify失败", zap.String("路径", absDir), zap.Error(err))
		}
		return err
	}

	fm.watchedDirs[absDir] = true // 标记此目录已成功添加到监控 (true表示目录)
	fm.logger.Info("成功添加目录到监控列表", zap.String("路径", absDir))
	return nil
}

// shouldIgnore 检查根据配置，给定的路径是否应该被忽略。
// 它会考虑ExcludePaths, ExcludeExt, 和 IncludeExt 配置。
func (fm *FilesystemMonitor) shouldIgnore(path string) bool {
	absPath, err := filepath.Abs(path) // 获取绝对路径
	if err != nil {
		fm.logger.Warn("无法获取绝对路径以进行忽略检查，将默认忽略此路径", zap.String("原始路径", path), zap.Error(err))
		return true // 对于有问题的路径，默认忽略
	}

	// 检查是否匹配任何排除路径规则
	for _, exclPattern := range fm.config.ExcludePaths {
		absExclPattern, err := filepath.Abs(exclPattern)
		if err != nil {
			fm.logger.Warn("无法获取排除规则的绝对路径，跳过此规则", zap.String("排除模式", exclPattern), zap.Error(err))
			continue
		}

		if !strings.ContainsAny(absExclPattern, "*?[") { // 如果排除规则不是glob模式 (即普通路径前缀)
			if strings.HasPrefix(absPath, absExclPattern) { // 如果路径以排除前缀开头
				return true // 忽略
			}
		} else { // 如果排除规则是glob模式
			// 将glob模式和目标路径都转换为系统特定的路径分隔符以进行匹配
			matchPattern := filepath.FromSlash(absExclPattern) 
			targetPathForMatch := filepath.FromSlash(absPath)
			matched, _ := filepath.Match(matchPattern, targetPathForMatch) // 执行glob匹配
			if matched {
				return true // 忽略
			}
		}
	}

	// 检查是否匹配任何排除扩展名规则
	ext := strings.ToLower(filepath.Ext(absPath)) // 获取并转换为小写的文件扩展名
	for _, excExt := range fm.config.ExcludeExt {
		if "."+strings.ToLower(strings.TrimPrefix(excExt, ".")) == ext { // 规范化扩展名并比较
			return true // 忽略
		}
	}

	// 如果定义了包含扩展名列表，则检查路径是否具有这些扩展名之一
	if len(fm.config.IncludeExt) > 0 {
		included := false
		for _, incExt := range fm.config.IncludeExt {
			if "."+strings.ToLower(strings.TrimPrefix(incExt, ".")) == ext { // 规范化扩展名并比较
				included = true
				break
			}
		}
		if !included { // 如果文件扩展名不在包含列表中
			return true // 忽略
		}
	}
	return false // 如果没有匹配任何忽略规则，则不忽略
}

// sendEvent 将组装好的FileEvent发送到事件通道。
// 如果通道已满，会记录警告并丢弃事件。
func (fm *FilesystemMonitor) sendEvent(event FileEvent) {
	select {
	case fm.eventChan <- event: // 尝试发送事件
		fm.logger.Debug("成功发送文件事件到通道",
			zap.String("类型", event.Type),
			zap.String("路径", event.Path),
			zap.String("旧路径", event.OldPath),
			zap.Bool("是否目录", event.IsDir))
	default: // 如果事件通道已满，无法立即发送
		fm.logger.Warn("事件通道已满，丢弃当前文件事件",
			zap.String("类型", event.Type),
			zap.String("路径", event.Path))
	}
}

// calculateFileHash 计算给定文件路径的内容哈希值。
// 它会根据配置选择哈希算法，并考虑MaxFileSize限制。
func (fm *FilesystemMonitor) calculateFileHash(filePath string) (string, error) {
	if !fm.config.CalculateHash { // 如果配置中禁用了哈希计算
		return "", nil
	}

	file, err := os.Open(filePath) // 打开文件
	if err != nil {
		return "", fmt.Errorf("打开文件失败 (%s): %v", filePath, err)
	}
	defer file.Close() //确保文件最终被关闭

	fi, err := file.Stat() // 获取文件信息
	if err != nil {
		return "", fmt.Errorf("获取文件状态失败 (%s): %v", filePath, err)
	}

	// 如果是目录、空文件或文件大小超过配置的最大限制，则不计算哈希
	if fi.IsDir() || fi.Size() == 0 || fi.Size() > fm.config.MaxFileSize {
		fm.logger.Debugw("跳过哈希计算 (目录/空文件/超大文件)", "路径", filePath, "大小", fi.Size(), "是否目录", fi.IsDir())
		return "", nil 
	}

	var h hash.Hash // 哈希接口
	selectedAlgo := strings.ToLower(fm.config.HashAlgorithm) // 获取配置的算法并转为小写
	fm.logger.Debugw("准备计算哈希", "文件路径", filePath, "配置算法", fm.config.HashAlgorithm, "选用算法", selectedAlgo)

	switch selectedAlgo { // 根据算法选择对应的哈希实现
	case "md5":
		h = md5.New()
		fm.logger.Debugw("使用MD5哈希算法")
	case "sha1":
		h = sha1.New()
		fm.logger.Debugw("使用SHA1哈希算法")
	case "sha256":
		h = sha256.New()
		fm.logger.Debugw("使用SHA256哈希算法")
	default:
		fm.logger.Errorw("不支持的哈希算法，无法计算哈希", "配置算法", fm.config.HashAlgorithm)
		return "", fmt.Errorf("不支持的哈希算法: %s", fm.config.HashAlgorithm)
	}

	// 将文件内容读入字节数组然后进行哈希计算
	fileBytes, err := ioutil.ReadAll(file) // 文件已被打开和Stat过
	if err != nil {
		return "", fmt.Errorf("读取文件内容以计算哈希失败 (%s): %v", filePath, err)
	}

	if _, err := h.Write(fileBytes); err != nil {
		// 对于内存中的哈希器，此写入错误不太可能发生，但检查一下总是好的
		return "", fmt.Errorf("将字节写入哈希器失败 (%s): %v", filePath, err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil // 计算哈希并以十六进制字符串形式返回
}