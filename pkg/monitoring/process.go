package monitoring

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ccnochch/edr-sdk-go/internal/logger"
	"go.uber.org/zap"
)

// ProcessEvent 进程事件
type ProcessEvent struct {
	Type           string            `json:"type"`       // create, exit, modify
	PID            int               `json:"pid"`        // 进程ID
	PPID           int               `json:"ppid"`       // 父进程ID
	Name           string            `json:"name"`       // 进程名称
	Cmdline        string            `json:"cmdline"`    // 命令行
	Exe            string            `json:"exe"`        // 可执行文件路径
	UID            int               `json:"uid"`        // 用户ID
	GID            int               `json:"gid"`        // 组ID
	StartTime      time.Time         `json:"start_time"` // 启动时间
	Timestamp      time.Time         `json:"timestamp"`  // 事件时间戳
	FormattedTime  string            `json:"formatted_time,omitempty"` // 格式化的启动时间
	TimeAnomaly    *TimeAnomalyInfo  `json:"time_anomaly,omitempty"`   // 时间异常信息
}

// ProcessInfo 进程信息
type ProcessInfo struct {
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	Name      string    `json:"name"`
	Cmdline   string    `json:"cmdline"`
	Exe       string    `json:"exe"`
	UID       int       `json:"uid"`
	GID       int       `json:"gid"`
	StartTime time.Time `json:"start_time"`
	CPUUsage  float64   `json:"cpu_usage"`
	MemUsage  int64     `json:"mem_usage"`
	Status    string    `json:"status"`
}

// TimeAnomalyInfo 时间异常信息
type TimeAnomalyInfo struct {
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	StartTime   time.Time `json:"start_time"`
	SystemTime  time.Time `json:"system_time"`
	TimeDiff    string    `json:"time_diff"`
	Description string    `json:"description"`
}

// ProcessMonitor 进程监控器
type ProcessMonitor struct {
	config       ProcessMonitorConfig
	logger       logger.Logger
	running      bool
	mu           sync.RWMutex
	processes    map[int]*ProcessInfo
	eventChan    chan ProcessEvent
	stopChan     chan struct{}
	wg           sync.WaitGroup
	bootTime     time.Time       // 缓存系统启动时间
	bootTimeMu   sync.RWMutex    // 系统启动时间缓存的互斥锁
	bootTimeSet  bool            // 系统启动时间是否已设置
}

// ProcessMonitorConfig 进程监控配置
type ProcessMonitorConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	Interval        time.Duration `mapstructure:"interval"`
	BufferSize      int           `mapstructure:"buffer_size"`
	Whitelist       []string      `mapstructure:"whitelist"`
	Blacklist       []string      `mapstructure:"blacklist"`
	TimeZone        string        `mapstructure:"time_zone"`         // 时区设置
	TimeFormat      string        `mapstructure:"time_format"`       // 时间格式
	AnomalyDetection bool         `mapstructure:"anomaly_detection"` // 是否启用异常检测
	MaxStartupDelay time.Duration `mapstructure:"max_startup_delay"` // 最大允许的启动延迟
}

// NewProcessMonitor 创建新的进程监控器
func NewProcessMonitor(config ProcessMonitorConfig) *ProcessMonitor {
	// 设置默认时区和时间格式
	if config.TimeZone == "" {
		config.TimeZone = "Local"
	}
	if config.TimeFormat == "" {
		config.TimeFormat = "2006-01-02 15:04:05"
	}
	if config.MaxStartupDelay == 0 {
		config.MaxStartupDelay = 5 * time.Minute
	}

	return &ProcessMonitor{
		config:    config,
		logger:    logger.Named("process-monitor"),
		processes: make(map[int]*ProcessInfo),
		eventChan: make(chan ProcessEvent, config.BufferSize),
		stopChan:  make(chan struct{}),
	}
}

// Start 启动进程监控
func (pm *ProcessMonitor) Start(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.running {
		return fmt.Errorf("进程监控器已经在运行")
	}

	if !pm.config.Enabled {
		pm.logger.Info("进程监控已禁用")
		return nil
	}

	pm.logger.Info("启动进程监控器",
		zap.Duration("interval", pm.config.Interval),
		zap.Int("buffer_size", pm.config.BufferSize),
	)

	pm.running = true

	// 初始化进程列表
	if err := pm.initProcessList(); err != nil {
		pm.logger.Error("初始化进程列表失败", zap.Error(err))
		return err
	}

	// 启动监控协程
	pm.wg.Add(1)
	go pm.monitorLoop(ctx)

	return nil
}

// Stop 停止进程监控
func (pm *ProcessMonitor) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.running {
		return nil
	}

	pm.logger.Info("停止进程监控器")
	pm.running = false
	close(pm.stopChan)
	pm.wg.Wait()
	close(pm.eventChan)

	return nil
}

// GetEventChannel 获取事件通道
func (pm *ProcessMonitor) GetEventChannel() <-chan ProcessEvent {
	return pm.eventChan
}

// GetProcessList 获取当前进程列表
func (pm *ProcessMonitor) GetProcessList() map[int]*ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make(map[int]*ProcessInfo)
	for pid, proc := range pm.processes {
		result[pid] = proc
	}
	return result
}

// GetProcessInfo 获取指定进程信息
func (pm *ProcessMonitor) GetProcessInfo(pid int) (*ProcessInfo, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	proc, exists := pm.processes[pid]
	return proc, exists
}

// initProcessList 初始化进程列表
func (pm *ProcessMonitor) initProcessList() error {
	processes, err := pm.scanProcesses()
	if err != nil {
		return err
	}

	pm.processes = processes
	pm.logger.Info("初始化进程列表完成", zap.Int("count", len(processes)))
	return nil
}

// monitorLoop 监控循环
func (pm *ProcessMonitor) monitorLoop(ctx context.Context) {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			pm.logger.Info("监控循环收到上下文取消信号")
			return
		case <-pm.stopChan:
			pm.logger.Info("监控循环收到停止信号")
			return
		case <-ticker.C:
			if err := pm.scanAndCompare(); err != nil {
				pm.logger.Error("扫描进程失败", zap.Error(err))
			}
		}
	}
}

// scanAndCompare 扫描并比较进程变化
func (pm *ProcessMonitor) scanAndCompare() error {
	currentProcesses, err := pm.scanProcesses()
	if err != nil {
		return err
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 检查新进程
	for pid, proc := range currentProcesses {
		if _, exists := pm.processes[pid]; !exists {
			// 新进程
			if pm.shouldMonitor(proc) {
				pm.processes[pid] = proc
				event := ProcessEvent{
					Type:      "create",
					PID:       proc.PID,
					PPID:      proc.PPID,
					Name:      proc.Name,
					Cmdline:   proc.Cmdline,
					Exe:       proc.Exe,
					UID:       proc.UID,
					GID:       proc.GID,
					StartTime: proc.StartTime,
					Timestamp: time.Now(),
					FormattedTime: pm.formatTime(proc.StartTime),
				}
				
				// 检测启动时间异常
				if pm.config.AnomalyDetection {
					anomaly := pm.detectTimeAnomaly(proc)
					if anomaly != nil {
						event.TimeAnomaly = anomaly
					}
				}
				
				pm.sendEvent(event)
			}
		}
	}

	// 检查退出的进程
	for pid, proc := range pm.processes {
		if _, exists := currentProcesses[pid]; !exists {
			// 进程已退出
			delete(pm.processes, pid)
			event := ProcessEvent{
				Type:      "exit",
				PID:       proc.PID,
				PPID:      proc.PPID,
				Name:      proc.Name,
				Cmdline:   proc.Cmdline,
				Exe:       proc.Exe,
				UID:       proc.UID,
				GID:       proc.GID,
				StartTime: proc.StartTime,
				Timestamp: time.Now(),
				FormattedTime: pm.formatTime(proc.StartTime),
			}
			pm.sendEvent(event)
		}
	}

	return nil
}

// scanProcesses 扫描当前系统进程
func (pm *ProcessMonitor) scanProcesses() (map[int]*ProcessInfo, error) {
	processes := make(map[int]*ProcessInfo)

	// 读取 /proc 目录
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("打开 /proc 目录失败: %v", err)
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("读取 /proc 目录失败: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 检查是否为数字目录名（PID）
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// 获取进程信息
		procInfo, err := pm.getProcessInfo(pid)
		if err != nil {
			// 进程可能已经退出，跳过
			continue
		}

		processes[pid] = procInfo
	}

	return processes, nil
}

// getProcessInfo 获取指定PID的进程信息
func (pm *ProcessMonitor) getProcessInfo(pid int) (*ProcessInfo, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	// 读取进程状态
	statPath := fmt.Sprintf("%s/stat", procPath)
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return nil, err
	}

	// 解析stat文件
	statFields := strings.Fields(string(statData))
	if len(statFields) < 24 {
		return nil, fmt.Errorf("stat文件格式不正确")
	}

	ppid, _ := strconv.Atoi(statFields[3])

	// 读取命令行
	cmdlinePath := fmt.Sprintf("%s/cmdline", procPath)
	cmdlineData, err := os.ReadFile(cmdlinePath)
	cmdline := ""
	if err == nil {
		cmdline = strings.ReplaceAll(string(cmdlineData), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
	}

	// 读取可执行文件路径
	exePath := fmt.Sprintf("%s/exe", procPath)
	exe, err := os.Readlink(exePath)
	if err != nil {
		exe = ""
	}

	// 获取进程名称
	name := statFields[1]
	if len(name) > 2 && name[0] == '(' && name[len(name)-1] == ')' {
		name = name[1 : len(name)-1]
	}

	// 读取状态信息
	statusPath := fmt.Sprintf("%s/status", procPath)
	statusData, err := os.ReadFile(statusPath)
	uid, gid := 0, 0
	if err == nil {
		lines := strings.Split(string(statusData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					uid, _ = strconv.Atoi(fields[1])
				}
			} else if strings.HasPrefix(line, "Gid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					gid, _ = strconv.Atoi(fields[1])
				}
			}
		}
	}

	// 计算进程启动时间
	startTime, err := pm.calculateStartTime(statFields)
	if err != nil {
		// 如果计算失败，使用当前时间作为回退方案
		pm.logger.Warn("计算进程启动时间失败，使用当前时间", 
			zap.Int("pid", pid), 
			zap.Error(err))
		startTime = time.Now()
	}

	return &ProcessInfo{
		PID:       pid,
		PPID:      ppid,
		Name:      name,
		Cmdline:   cmdline,
		Exe:       exe,
		UID:       uid,
		GID:       gid,
		StartTime: startTime,
		Status:    "running",
	}, nil
}

// calculateStartTime 计算进程的实际启动时间
func (pm *ProcessMonitor) calculateStartTime(statFields []string) (time.Time, error) {
	// 获取系统启动时间
	bootTime, err := pm.getSystemBootTime()
	if err != nil {
		return time.Time{}, fmt.Errorf("获取系统启动时间失败: %v", err)
	}

	// 获取进程启动时间(jiffies)
	// stat文件中第22个字段是进程创建时间（相对于系统启动时间的jiffies）
	startTimeJiffies, err := strconv.ParseInt(statFields[21], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析进程启动时间失败: %v", err)
	}

	// 将jiffies转换为秒，Linux系统中一般为100 HZ (即每秒100个时钟滴答)
	// 但不同系统可能不同，理想情况下应该从sysconf(_SC_CLK_TCK)获取
	const clockTicksPerSecond = 100
	startTimeSecs := float64(startTimeJiffies) / clockTicksPerSecond

	// 计算Unix时间戳
	unixStartTime := bootTime.Unix() + int64(startTimeSecs)
	
	return time.Unix(unixStartTime, 0), nil
}

// getSystemBootTime 获取系统启动时间
func (pm *ProcessMonitor) getSystemBootTime() (time.Time, error) {
	// 检查缓存
	pm.bootTimeMu.RLock()
	if pm.bootTimeSet {
		bootTime := pm.bootTime
		pm.bootTimeMu.RUnlock()
		return bootTime, nil
	}
	pm.bootTimeMu.RUnlock()

	// 如果缓存未设置，则从系统获取
	var bootTime time.Time
	var err error

	// 从/proc/stat读取系统启动时间
	statData, err := os.ReadFile("/proc/stat")
	if err == nil {
		lines := strings.Split(string(statData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "btime ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					bootTimeSecs, err := strconv.ParseInt(fields[1], 10, 64)
					if err == nil {
						bootTime = time.Unix(bootTimeSecs, 0)
						// 设置缓存
						pm.bootTimeMu.Lock()
						pm.bootTime = bootTime
						pm.bootTimeSet = true
						pm.bootTimeMu.Unlock()
						return bootTime, nil
					}
				}
			}
		}
	}

	// 如果找不到btime，尝试使用uptime命令
	bootTime, err = pm.getBootTimeFromUptime()
	if err == nil {
		// 设置缓存
		pm.bootTimeMu.Lock()
		pm.bootTime = bootTime
		pm.bootTimeSet = true
		pm.bootTimeMu.Unlock()
	}
	return bootTime, err
}

// getBootTimeFromUptime 通过uptime命令获取系统启动时间
func (pm *ProcessMonitor) getBootTimeFromUptime() (time.Time, error) {
	// 读取/proc/uptime获取系统运行时间
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, err
	}

	fields := strings.Fields(string(uptimeData))
	if len(fields) < 1 {
		return time.Time{}, fmt.Errorf("解析uptime失败")
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析uptime值失败: %v", err)
	}

	// 当前时间减去系统运行时间
	now := time.Now()
	bootTime := now.Add(-time.Duration(uptime * float64(time.Second)))
	
	return bootTime, nil
}

// shouldMonitor 检查是否应该监控该进程
func (pm *ProcessMonitor) shouldMonitor(proc *ProcessInfo) bool {
	// 检查黑名单
	for _, pattern := range pm.config.Blacklist {
		if strings.Contains(proc.Name, pattern) || strings.Contains(proc.Cmdline, pattern) {
			return false
		}
	}

	// 检查白名单（如果配置了白名单）
	if len(pm.config.Whitelist) > 0 {
		for _, pattern := range pm.config.Whitelist {
			if strings.Contains(proc.Name, pattern) || strings.Contains(proc.Cmdline, pattern) {
				return true
			}
		}
		return false
	}

	return true
}

// formatTime 格式化时间到指定时区和格式
func (pm *ProcessMonitor) formatTime(t time.Time) string {
	// 获取指定时区
	loc, err := time.LoadLocation(pm.config.TimeZone)
	if err != nil {
		// 如果时区无效，使用本地时区
		pm.logger.Warn("无效的时区设置，使用本地时区", 
			zap.String("timezone", pm.config.TimeZone),
			zap.Error(err))
		loc = time.Local
	}
	
	// 转换到指定时区并格式化
	return t.In(loc).Format(pm.config.TimeFormat)
}

// detectTimeAnomaly 检测进程启动时间异常
func (pm *ProcessMonitor) detectTimeAnomaly(proc *ProcessInfo) *TimeAnomalyInfo {
	now := time.Now()
	
	// 检测过去启动的进程（将来的时间明显异常）
	if proc.StartTime.After(now) {
		diff := proc.StartTime.Sub(now)
		return &TimeAnomalyInfo{
			PID:         proc.PID,
			Name:        proc.Name,
			StartTime:   proc.StartTime,
			SystemTime:  now,
			TimeDiff:    fmt.Sprintf("+%s", diff.String()),
			Description: "进程启动时间在系统当前时间之后，可能是时钟篡改",
		}
	}
	
	// 检测启动时间接近当前时间，但创建事件被延迟通知的情况
	// 这可能是正常的，但也可能是攻击者尝试隐藏进程创建事件
	timeSinceStart := now.Sub(proc.StartTime)
	if timeSinceStart > pm.config.MaxStartupDelay {
		return &TimeAnomalyInfo{
			PID:         proc.PID,
			Name:        proc.Name,
			StartTime:   proc.StartTime,
			SystemTime:  now,
			TimeDiff:    fmt.Sprintf("-%s", timeSinceStart.String()),
			Description: "进程创建事件的延迟通知时间异常长，可能是尝试逃避检测",
		}
	}
	
	return nil
}

// sendEvent 发送事件
func (pm *ProcessMonitor) sendEvent(event ProcessEvent) {
	select {
	case pm.eventChan <- event:
		// 检查是否存在时间异常
		if event.TimeAnomaly != nil {
			pm.logger.Warn("检测到进程时间异常",
				zap.String("type", event.Type),
				zap.Int("pid", event.PID),
				zap.String("name", event.Name),
				zap.String("description", event.TimeAnomaly.Description),
				zap.String("time_diff", event.TimeAnomaly.TimeDiff),
			)
		} else {
			pm.logger.Debug("发送进程事件",
				zap.String("type", event.Type),
				zap.Int("pid", event.PID),
				zap.String("name", event.Name),
			)
		}
	default:
		pm.logger.Warn("事件通道已满，丢弃事件",
			zap.String("type", event.Type),
			zap.Int("pid", event.PID),
		)
	}
} 