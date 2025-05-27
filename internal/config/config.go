package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Config 主配置结构
type Config struct {
	// 基础配置
	Agent     AgentConfig     `mapstructure:"agent"`
	Logging   LoggingConfig   `mapstructure:"logging"`
	
	// 功能模块配置
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
	Detection  DetectionConfig  `mapstructure:"detection"`
	Collection CollectionConfig `mapstructure:"collection"`
	Response   ResponseConfig   `mapstructure:"response"`
	
	// 集成配置
	Integration IntegrationConfig `mapstructure:"integration"`
	Reporting   ReportingConfig   `mapstructure:"reporting"`
}

// AgentConfig 代理配置
type AgentConfig struct {
	Name        string        `mapstructure:"name"`
	Version     string        `mapstructure:"version"`
	Environment string        `mapstructure:"environment"`
	DataDir     string        `mapstructure:"data_dir"`
	PidFile     string        `mapstructure:"pid_file"`
	Interval    time.Duration `mapstructure:"interval"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

// MonitoringConfig 监控配置
type MonitoringConfig struct {
	Process    ProcessMonitorConfig    `mapstructure:"process"`
	FileSystem FileSystemMonitorConfig `mapstructure:"filesystem"`
	Network    NetworkMonitorConfig    `mapstructure:"network"`
	Syscall    SyscallMonitorConfig    `mapstructure:"syscall"`
}

// ProcessMonitorConfig 进程监控配置
type ProcessMonitorConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	Interval    time.Duration `mapstructure:"interval"`
	BufferSize  int           `mapstructure:"buffer_size"`
	Whitelist   []string      `mapstructure:"whitelist"`
	Blacklist   []string      `mapstructure:"blacklist"`
}

// FileSystemMonitorConfig 文件系统监控配置
type FileSystemMonitorConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	WatchPaths  []string `mapstructure:"watch_paths"`
	IgnorePaths []string `mapstructure:"ignore_paths"`
	Events      []string `mapstructure:"events"`
	Recursive   bool     `mapstructure:"recursive"`
}

// NetworkMonitorConfig 网络监控配置
type NetworkMonitorConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	Interfaces  []string `mapstructure:"interfaces"`
	Protocols   []string `mapstructure:"protocols"`
	Ports       []int    `mapstructure:"ports"`
	BufferSize  int      `mapstructure:"buffer_size"`
}

// SyscallMonitorConfig 系统调用监控配置
type SyscallMonitorConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Syscalls  []string `mapstructure:"syscalls"`
	Processes []string `mapstructure:"processes"`
}

// DetectionConfig 检测配置
type DetectionConfig struct {
	Enabled    bool                    `mapstructure:"enabled"`
	Rules      RulesConfig             `mapstructure:"rules"`
	IOC        IOCConfig               `mapstructure:"ioc"`
	Behavioral BehavioralConfig        `mapstructure:"behavioral"`
	ML         MachineLearningConfig   `mapstructure:"ml"`
}

// RulesConfig 规则配置
type RulesConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	RulesDir  string   `mapstructure:"rules_dir"`
	RuleFiles []string `mapstructure:"rule_files"`
	AutoLoad  bool     `mapstructure:"auto_load"`
}

// IOCConfig IOC配置
type IOCConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Sources   []string `mapstructure:"sources"`
	UpdateInterval time.Duration `mapstructure:"update_interval"`
	CacheSize int      `mapstructure:"cache_size"`
}

// BehavioralConfig 行为分析配置
type BehavioralConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	WindowSize    time.Duration `mapstructure:"window_size"`
	Threshold     float64       `mapstructure:"threshold"`
	BaselineFile  string        `mapstructure:"baseline_file"`
}

// MachineLearningConfig 机器学习配置
type MachineLearningConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	ModelPath  string `mapstructure:"model_path"`
	Threshold  float64 `mapstructure:"threshold"`
	Features   []string `mapstructure:"features"`
}

// CollectionConfig 数据收集配置
type CollectionConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	StoragePath string        `mapstructure:"storage_path"`
	MaxSize     int64         `mapstructure:"max_size"`
	Retention   time.Duration `mapstructure:"retention"`
	Compression bool          `mapstructure:"compression"`
}

// ResponseConfig 响应配置
type ResponseConfig struct {
	Enabled   bool                    `mapstructure:"enabled"`
	Actions   []ResponseActionConfig  `mapstructure:"actions"`
	Timeout   time.Duration          `mapstructure:"timeout"`
	DryRun    bool                   `mapstructure:"dry_run"`
}

// ResponseActionConfig 响应动作配置
type ResponseActionConfig struct {
	Type      string                 `mapstructure:"type"`
	Enabled   bool                   `mapstructure:"enabled"`
	Params    map[string]interface{} `mapstructure:"params"`
	Condition string                 `mapstructure:"condition"`
}

// IntegrationConfig 集成配置
type IntegrationConfig struct {
	SIEM      SIEMConfig      `mapstructure:"siem"`
	ThreatIntel ThreatIntelConfig `mapstructure:"threat_intel"`
	Cloud     CloudConfig     `mapstructure:"cloud"`
}

// SIEMConfig SIEM集成配置
type SIEMConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Type     string `mapstructure:"type"`
	Endpoint string `mapstructure:"endpoint"`
	APIKey   string `mapstructure:"api_key"`
	Format   string `mapstructure:"format"`
}

// ThreatIntelConfig 威胁情报配置
type ThreatIntelConfig struct {
	Enabled   bool     `mapstructure:"enabled"`
	Sources   []string `mapstructure:"sources"`
	APIKeys   map[string]string `mapstructure:"api_keys"`
	UpdateInterval time.Duration `mapstructure:"update_interval"`
}

// CloudConfig 云集成配置
type CloudConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Provider string `mapstructure:"provider"`
	Region   string `mapstructure:"region"`
	Credentials map[string]string `mapstructure:"credentials"`
}

// ReportingConfig 报告配置
type ReportingConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	OutputDir   string        `mapstructure:"output_dir"`
	Format      []string      `mapstructure:"format"`
	Schedule    string        `mapstructure:"schedule"`
	Recipients  []string      `mapstructure:"recipients"`
	Retention   time.Duration `mapstructure:"retention"`
}

// 全局配置实例
var globalConfig *Config

// setDefaults 设置默认配置值
func setDefaults() {
	// Agent 默认配置
	viper.SetDefault("agent.name", "edr-agent")
	viper.SetDefault("agent.version", "1.0.0")
	viper.SetDefault("agent.environment", "production")
	viper.SetDefault("agent.data_dir", "/var/lib/edr")
	viper.SetDefault("agent.pid_file", "/var/run/edr-agent.pid")
	viper.SetDefault("agent.interval", "30s")

	// Logging 默认配置
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "/var/log/edr/agent.log")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 3)
	viper.SetDefault("logging.max_age", 28)
	viper.SetDefault("logging.compress", true)

	// Monitoring 默认配置
	viper.SetDefault("monitoring.process.enabled", true)
	viper.SetDefault("monitoring.process.interval", "5s")
	viper.SetDefault("monitoring.process.buffer_size", 1000)
	viper.SetDefault("monitoring.process.whitelist", []string{})
	viper.SetDefault("monitoring.process.blacklist", []string{})

	viper.SetDefault("monitoring.filesystem.enabled", true)
	viper.SetDefault("monitoring.filesystem.watch_paths", []string{"/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"})
	viper.SetDefault("monitoring.filesystem.ignore_paths", []string{"/proc", "/sys", "/dev"})
	viper.SetDefault("monitoring.filesystem.events", []string{"create", "modify", "delete"})
	viper.SetDefault("monitoring.filesystem.recursive", true)

	viper.SetDefault("monitoring.network.enabled", true)
	viper.SetDefault("monitoring.network.interfaces", []string{"eth0", "wlan0"})
	viper.SetDefault("monitoring.network.protocols", []string{"tcp", "udp"})
	viper.SetDefault("monitoring.network.ports", []int{})
	viper.SetDefault("monitoring.network.buffer_size", 1000)

	viper.SetDefault("monitoring.syscall.enabled", false)
	viper.SetDefault("monitoring.syscall.syscalls", []string{"execve", "open", "connect"})
	viper.SetDefault("monitoring.syscall.processes", []string{})

	// Detection 默认配置
	viper.SetDefault("detection.enabled", true)
	viper.SetDefault("detection.rules.enabled", true)
	viper.SetDefault("detection.rules.rules_dir", "/etc/edr/rules")
	viper.SetDefault("detection.rules.rule_files", []string{})
	viper.SetDefault("detection.rules.auto_load", true)

	viper.SetDefault("detection.ioc.enabled", true)
	viper.SetDefault("detection.ioc.sources", []string{})
	viper.SetDefault("detection.ioc.update_interval", "24h")
	viper.SetDefault("detection.ioc.cache_size", 10000)

	viper.SetDefault("detection.behavioral.enabled", true)
	viper.SetDefault("detection.behavioral.window_size", "15m")
	viper.SetDefault("detection.behavioral.threshold", 0.8)
	viper.SetDefault("detection.behavioral.baseline_file", "/etc/edr/baseline.json")

	viper.SetDefault("detection.ml.enabled", false)
	viper.SetDefault("detection.ml.model_path", "/etc/edr/models/threat_detection.model")
	viper.SetDefault("detection.ml.threshold", 0.7)
	viper.SetDefault("detection.ml.features", []string{})

	// Collection 默认配置
	viper.SetDefault("collection.enabled", true)
	viper.SetDefault("collection.storage_path", "/var/lib/edr/data")
	viper.SetDefault("collection.max_size", 1073741824) // 1GB
	viper.SetDefault("collection.retention", "720h")    // 30 days
	viper.SetDefault("collection.compression", true)

	// Response 默认配置
	viper.SetDefault("response.enabled", true)
	viper.SetDefault("response.actions", []ResponseActionConfig{})
	viper.SetDefault("response.timeout", "5m")
	viper.SetDefault("response.dry_run", false)

	// Integration 默认配置
	viper.SetDefault("integration.siem.enabled", false)
	viper.SetDefault("integration.siem.type", "")
	viper.SetDefault("integration.siem.endpoint", "")
	viper.SetDefault("integration.siem.api_key", "")
	viper.SetDefault("integration.siem.format", "json")

	viper.SetDefault("integration.threat_intel.enabled", false)
	viper.SetDefault("integration.threat_intel.sources", []string{})
	viper.SetDefault("integration.threat_intel.api_keys", map[string]string{})
	viper.SetDefault("integration.threat_intel.update_interval", "6h")

	viper.SetDefault("integration.cloud.enabled", false)
	viper.SetDefault("integration.cloud.provider", "")
	viper.SetDefault("integration.cloud.region", "")
	viper.SetDefault("integration.cloud.credentials", map[string]string{})

	// Reporting 默认配置
	viper.SetDefault("reporting.enabled", true)
	viper.SetDefault("reporting.output_dir", "/var/lib/edr/reports")
	viper.SetDefault("reporting.format", []string{"json", "html"})
	viper.SetDefault("reporting.schedule", "0 0 * * *") // 每天午夜
	viper.SetDefault("reporting.recipients", []string{})
	viper.SetDefault("reporting.retention", "2160h") // 90 days
}

// InitConfig 初始化配置
func InitConfig(configPath string) (*Config, error) {
	// 设置默认值
	setDefaults()

	// 配置文件名和路径
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		// 默认配置文件搜索路径
		viper.SetConfigName("edr")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/edr/")
		viper.AddConfigPath("$HOME/.edr")
		viper.AddConfigPath(".")
	}

	// 环境变量前缀
	viper.SetEnvPrefix("EDR")
	viper.AutomaticEnv()
	
	// 环境变量键名替换
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// 配置文件未找到，使用默认配置
			fmt.Printf("配置文件未找到，使用默认配置\n")
		} else {
			return nil, fmt.Errorf("读取配置文件失败: %v", err)
		}
	}

	// 解析配置到结构体
	config := &Config{}
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("解析配置失败: %v", err)
	}

	// 验证配置
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	globalConfig = config
	return config, nil
}

// GetConfig 获取全局配置
func GetConfig() *Config {
	if globalConfig == nil {
		// 如果没有初始化，使用默认配置
		config, _ := InitConfig("")
		return config
	}
	return globalConfig
}

// SaveConfig 保存配置到文件
func SaveConfig(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("配置文件路径不能为空")
	}

	// 确保目录存在
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %v", err)
	}

	// 写入配置文件
	if err := viper.WriteConfigAs(configPath); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	return nil
}

// ReloadConfig 重新加载配置
func ReloadConfig() error {
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("重新加载配置失败: %v", err)
	}

	config := &Config{}
	if err := viper.Unmarshal(config); err != nil {
		return fmt.Errorf("解析配置失败: %v", err)
	}

	if err := config.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %v", err)
	}

	globalConfig = config
	return nil
}

// WatchConfig 监控配置文件变化
func WatchConfig(callback func()) {
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Printf("配置文件发生变化: %s\n", e.Name)
		if err := ReloadConfig(); err != nil {
			fmt.Printf("重新加载配置失败: %v\n", err)
		} else {
			if callback != nil {
				callback()
			}
		}
	})
}

// Validate 验证配置
func (c *Config) Validate() error {
	// 验证基础配置
	if c.Agent.Name == "" {
		return fmt.Errorf("代理名称不能为空")
	}

	if c.Agent.DataDir == "" {
		return fmt.Errorf("数据目录不能为空")
	}

	// 验证日志配置
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true, "panic": true,
	}
	if !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("无效的日志级别: %s", c.Logging.Level)
	}

	// 验证监控配置
	if c.Monitoring.Process.Enabled && c.Monitoring.Process.Interval <= 0 {
		return fmt.Errorf("进程监控间隔必须大于0")
	}

	// 验证存储配置
	if c.Collection.Enabled && c.Collection.MaxSize <= 0 {
		return fmt.Errorf("存储最大大小必须大于0")
	}

	return nil
}

// GetString 获取字符串配置值
func GetString(key string) string {
	return viper.GetString(key)
}

// GetInt 获取整数配置值
func GetInt(key string) int {
	return viper.GetInt(key)
}

// GetBool 获取布尔配置值
func GetBool(key string) bool {
	return viper.GetBool(key)
}

// GetDuration 获取时间间隔配置值
func GetDuration(key string) time.Duration {
	return viper.GetDuration(key)
}

// GetStringSlice 获取字符串切片配置值
func GetStringSlice(key string) []string {
	return viper.GetStringSlice(key)
}

// Set 设置配置值
func Set(key string, value interface{}) {
	viper.Set(key, value)
} 