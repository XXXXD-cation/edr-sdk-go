package monitoring

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/XXXXD-cation/edr-sdk-go/internal/logger"
)

func init() {
	// 初始化测试环境的日志系统
	logConfig := logger.LogConfig{
		Level:  "debug",
		Format: "console",
		Output: "stdout",
	}
	logger.InitGlobalLogger(logConfig)
}

func TestNewProcessMonitor(t *testing.T) {
	// 测试默认配置
	config := ProcessMonitorConfig{
		Enabled:    true,
		Interval:   time.Second * 3,
		BufferSize: 100,
	}

	monitor := NewProcessMonitor(config)
	
	if monitor == nil {
		t.Fatal("NewProcessMonitor 返回 nil")
	}
	
	if monitor.config.Interval != time.Second*3 {
		t.Errorf("预期的间隔时间为 %v，得到 %v", time.Second*3, monitor.config.Interval)
	}
	
	if monitor.config.BufferSize != 100 {
		t.Errorf("预期的缓冲区大小为 100，得到 %v", monitor.config.BufferSize)
	}
	
	// 检查默认值设置
	config = ProcessMonitorConfig{
		Enabled: true,
	}
	
	monitor = NewProcessMonitor(config)
	
	if monitor.config.TimeZone == "" {
		t.Error("时区应该设置默认值")
	}
	
	if monitor.config.TimeFormat == "" {
		t.Error("时间格式应该设置默认值")
	}
	
	if monitor.config.MaxStartupDelay == 0 {
		t.Error("最大启动延迟应该设置默认值")
	}
}

func TestProcessMonitorStartAndStop(t *testing.T) {
	config := ProcessMonitorConfig{
		Enabled:    true,
		Interval:   time.Millisecond * 100, // 使用较短的间隔以加快测试
		BufferSize: 10,
	}
	
	monitor := NewProcessMonitor(config)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// 测试启动
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("启动进程监控失败: %v", err)
	}
	
	// 检查是否正在运行
	monitor.mu.RLock()
	running := monitor.running
	monitor.mu.RUnlock()
	
	if !running {
		t.Error("进程监控器应该处于运行状态")
	}
	
	// 测试重复启动
	err = monitor.Start(ctx)
	if err == nil {
		t.Error("重复启动应该返回错误")
	}
	
	// 等待一小段时间以确保监控循环有机会运行
	time.Sleep(time.Millisecond * 200)
	
	// 测试停止
	err = monitor.Stop()
	if err != nil {
		t.Fatalf("停止进程监控失败: %v", err)
	}
	
	// 检查是否已停止
	monitor.mu.RLock()
	running = monitor.running
	monitor.mu.RUnlock()
	
	if running {
		t.Error("进程监控器应该已停止")
	}
	
	// 测试重复停止
	err = monitor.Stop()
	if err != nil {
		t.Error("重复停止不应该返回错误")
	}
}

func TestProcessMonitorGetters(t *testing.T) {
	config := ProcessMonitorConfig{
		Enabled:    true,
		Interval:   time.Second,
		BufferSize: 5,
	}
	
	monitor := NewProcessMonitor(config)
	
	// 测试GetEventChannel
	eventChan := monitor.GetEventChannel()
	if eventChan == nil {
		t.Error("GetEventChannel 不应该返回 nil")
	}
	
	// 添加一些模拟进程
	monitor.mu.Lock()
	monitor.processes = map[int]*ProcessInfo{
		1: {PID: 1, Name: "init"},
		2: {PID: 2, Name: "test"},
	}
	monitor.mu.Unlock()
	
	// 测试GetProcessList
	procList := monitor.GetProcessList()
	if len(procList) != 2 {
		t.Errorf("GetProcessList 返回的进程数量错误，预期为 2，得到 %d", len(procList))
	}
	
	// 测试GetProcessInfo
	proc, exists := monitor.GetProcessInfo(1)
	if !exists {
		t.Error("GetProcessInfo 应该返回存在的进程")
	}
	if proc.PID != 1 || proc.Name != "init" {
		t.Errorf("GetProcessInfo 返回的进程信息错误，预期 PID: 1, Name: init，得到 PID: %d, Name: %s", proc.PID, proc.Name)
	}
	
	// 测试不存在的进程
	_, exists = monitor.GetProcessInfo(999)
	if exists {
		t.Error("GetProcessInfo 不应该返回不存在的进程")
	}
}

func TestCalculateStartTime(t *testing.T) {
	// 跳过此测试如果不是在 Linux 上运行
	if _, err := os.Stat("/proc"); os.IsNotExist(err) {
		t.Skip("不是 Linux 系统，跳过测试")
	}
	
	monitor := NewProcessMonitor(ProcessMonitorConfig{
		Enabled:    true,
		Interval:   time.Second,
		BufferSize: 5,
	})
	
	// 从 /proc/self/stat 获取当前进程的信息
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatalf("读取 /proc/self/stat 失败: %v", err)
	}
	
	statFields := splitStatFields(string(data))
	if len(statFields) < 22 {
		t.Fatal("stat 字段数量不足")
	}
	
	// 计算当前进程的启动时间
	startTime, err := monitor.calculateStartTime(statFields)
	if err != nil {
		t.Fatalf("计算启动时间失败: %v", err)
	}
	
	// 验证启动时间是否合理（不应该是未来时间或太久以前）
	now := time.Now()
	if startTime.After(now) {
		t.Errorf("启动时间不应该是未来时间: %v > %v", startTime, now)
	}
	
	// 启动时间应该在合理范围内（如一周内）
	weekAgo := now.Add(-7 * 24 * time.Hour)
	if startTime.Before(weekAgo) {
		t.Logf("注意: 计算的启动时间可能太早: %v < %v", startTime, weekAgo)
	}
}

func TestTimeAnomalyDetection(t *testing.T) {
	monitor := NewProcessMonitor(ProcessMonitorConfig{
		Enabled:         true,
		Interval:        time.Second,
		BufferSize:      5,
		AnomalyDetection: true,
		MaxStartupDelay: time.Minute * 5,
	})
	
	// 测试未来时间异常
	futureProc := &ProcessInfo{
		PID:       1000,
		Name:      "future_process",
		StartTime: time.Now().Add(time.Hour), // 未来一小时
	}
	
	anomaly := monitor.detectTimeAnomaly(futureProc)
	if anomaly == nil {
		t.Error("未能检测到未来时间异常")
	} else {
		if anomaly.PID != 1000 || anomaly.Name != "future_process" {
			t.Errorf("异常信息错误, PID: %d, Name: %s", anomaly.PID, anomaly.Name)
		}
		if anomaly.TimeDiff[0] != '+' {
			t.Errorf("未来时间差异应该以 + 开头，但得到 %s", anomaly.TimeDiff)
		}
	}
	
	// 测试长延迟启动异常
	oldProc := &ProcessInfo{
		PID:       1001,
		Name:      "old_process",
		StartTime: time.Now().Add(-6 * time.Hour), // 6小时前
	}
	
	anomaly = monitor.detectTimeAnomaly(oldProc)
	if anomaly == nil {
		t.Error("未能检测到长延迟启动异常")
	} else {
		if anomaly.PID != 1001 || anomaly.Name != "old_process" {
			t.Errorf("异常信息错误, PID: %d, Name: %s", anomaly.PID, anomaly.Name)
		}
		if anomaly.TimeDiff[0] != '-' {
			t.Errorf("延迟时间差异应该以 - 开头，但得到 %s", anomaly.TimeDiff)
		}
	}
	
	// 测试正常情况
	normalProc := &ProcessInfo{
		PID:       1002,
		Name:      "normal_process",
		StartTime: time.Now().Add(-time.Minute), // 一分钟前
	}
	
	anomaly = monitor.detectTimeAnomaly(normalProc)
	if anomaly != nil {
		t.Errorf("正常进程不应该检测到异常: %+v", anomaly)
	}
}

// 辅助函数：分割 stat 文件字段，处理进程名中可能包含空格的情况
func splitStatFields(stat string) []string {
	result := make([]string, 0, 52) // stat 通常有 52 个字段
	
	// 找到第一个左括号，它标志着进程名的开始
	startIdx := -1
	for i, c := range stat {
		if c == '(' {
			startIdx = i
			break
		}
	}
	
	if startIdx == -1 {
		return []string{}
	}
	
	// 找到最后一个右括号，它标志着进程名的结束
	endIdx := -1
	for i := len(stat) - 1; i >= 0; i-- {
		if stat[i] == ')' {
			endIdx = i
			break
		}
	}
	
	if endIdx == -1 {
		return []string{}
	}
	
	// 分割 stat 字符串
	// 1. 添加 PID
	if startIdx > 0 {
		result = append(result, stat[:startIdx-1])
	}
	
	// 2. 添加进程名（包括括号）
	result = append(result, stat[startIdx-1:endIdx+1])
	
	// 3. 添加剩余字段
	remaining := stat[endIdx+2:] // +2 跳过右括号和随后的空格
	
	// 按空格分割剩余部分
	var field string
	for i := 0; i < len(remaining); i++ {
		if remaining[i] == ' ' {
			if field != "" {
				result = append(result, field)
				field = ""
			}
		} else {
			field += string(remaining[i])
		}
	}
	
	// 添加最后一个字段
	if field != "" {
		result = append(result, field)
	}
	
	return result
} 