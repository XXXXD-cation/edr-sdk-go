package monitoring

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/XXXXD-cation/edr-sdk-go/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hash"
)

// testLogConfig 是用于测试的特定日志配置
var testLogConfig = logger.LogConfig{
	Level:  "debug", // 在测试期间使用debug级别可以输出更详细的日志信息
	Format: "console",
	Output: "stdout",
}

func init() {
	// 初始化全局日志记录器，供测试使用
	logger.InitGlobalLogger(testLogConfig)
}

// TestNewFilesystemMonitor_Defaults 测试NewFilesystemMonitor函数是否正确设置了默认配置值
func TestNewFilesystemMonitor_Defaults(t *testing.T) {
	config := FilesystemMonitorConfig{}
	monitor := NewFilesystemMonitor(config)

	assert.Equal(t, 1000, monitor.config.BufferSize, "默认BufferSize应为1000")
	assert.Equal(t, int64(10*1024*1024), monitor.config.MaxFileSize, "默认MaxFileSize应为10MB")
	assert.Equal(t, "sha256", monitor.config.HashAlgorithm, "默认HashAlgorithm应为sha256")
	assert.Equal(t, 2*time.Second, monitor.config.RenameMatchWindow, "默认RenameMatchWindow应为2秒")
	assert.Equal(t, 5*time.Second, monitor.config.RenameCleanupInterval, "默认RenameCleanupInterval应为5秒")
}

// TestNewFilesystemMonitor_Custom 测试NewFilesystemMonitor函数是否能正确应用自定义配置值
func TestNewFilesystemMonitor_Custom(t *testing.T) {
	config := FilesystemMonitorConfig{
		Enabled:             true,
		WatchPaths:          []string{"/tmp/test1", "/var/log"},
		RecursiveWatch:      true,
		ExcludePaths:        []string{"/tmp/test1/ignore"},
		IncludeExt:          []string{".log"},
		ExcludeExt:          []string{".tmp"},
		BufferSize:          500,
		HashAlgorithm:       "md5",
		CalculateHash:       true,
		MaxFileSize:         1024,
		RenameMatchWindow:   1 * time.Second,
		RenameCleanupInterval: 3 * time.Second,
	}
	monitor := NewFilesystemMonitor(config)

	assert.Equal(t, config.Enabled, monitor.config.Enabled)
	assert.Equal(t, config.WatchPaths, monitor.config.WatchPaths)
	assert.Equal(t, config.RecursiveWatch, monitor.config.RecursiveWatch)
	assert.Equal(t, config.ExcludePaths, monitor.config.ExcludePaths)
	assert.Equal(t, config.IncludeExt, monitor.config.IncludeExt)
	assert.Equal(t, config.ExcludeExt, monitor.config.ExcludeExt)
	assert.Equal(t, config.BufferSize, monitor.config.BufferSize)
	assert.Equal(t, config.HashAlgorithm, monitor.config.HashAlgorithm)
	assert.Equal(t, config.CalculateHash, monitor.config.CalculateHash)
	assert.Equal(t, config.MaxFileSize, monitor.config.MaxFileSize)
	assert.Equal(t, config.RenameMatchWindow, monitor.config.RenameMatchWindow)
	assert.Equal(t, config.RenameCleanupInterval, monitor.config.RenameCleanupInterval)
}

// TestShouldIgnore 测试shouldIgnore方法的各种忽略逻辑
func TestShouldIgnore(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "shouldignore_test") // 为测试创建临时目录
	require.NoError(t, err)
	defer os.RemoveAll(tempDir) // 测试结束后清理临时目录

	tests := []struct {
		name         string                        // 测试用例名称
		config       FilesystemMonitorConfig       // 测试用的监控配置
		path         string                        // 被检查的路径
		expectedIgnore bool                          // 预期shouldIgnore的返回值
	}{
		{
			name: "基本排除路径前缀", // Test case: basic exclude path prefix
			config: FilesystemMonitorConfig{
				ExcludePaths: []string{filepath.Join(tempDir, "ignore_this_dir")},
			},
			path:         filepath.Join(tempDir, "ignore_this_dir", "file.txt"),
			expectedIgnore: true,
		},
		{
			name: "基本排除路径通配符", // Test case: basic exclude path wildcard
			config: FilesystemMonitorConfig{
				ExcludePaths: []string{filepath.Join(tempDir, "temp*")},
			},
			path:         filepath.Join(tempDir, "temporary_file.dat"),
			expectedIgnore: true,
		},
		{
			name: "路径不在排除列表中", // Test case: not in exclude path
			config: FilesystemMonitorConfig{
				ExcludePaths: []string{filepath.Join(tempDir, "specific_exclude")},
			},
			path:         filepath.Join(tempDir, "other_dir", "file.txt"),
			expectedIgnore: false,
		},
		{
			name: "排除特定扩展名", // Test case: exclude extension
			config: FilesystemMonitorConfig{
				ExcludeExt: []string{".tmp", ".swp"},
			},
			path:         filepath.Join(tempDir, "document.tmp"),
			expectedIgnore: true,
		},
		{
			name: "包含特定扩展名 - 匹配", // Test case: include extension - match
			config: FilesystemMonitorConfig{
				IncludeExt: []string{".log", ".txt"},
			},
			path:         filepath.Join(tempDir, "app.log"),
			expectedIgnore: false,
		},
		{
			name: "包含特定扩展名 - 不匹配", // Test case: include extension - no match
			config: FilesystemMonitorConfig{
				IncludeExt: []string{".log", ".txt"},
			},
			path:         filepath.Join(tempDir, "image.jpg"),
			expectedIgnore: true,
		},
		{
			name: "同时使用包含和排除扩展名 - 排除优先", // Test case: include and exclude extension - exclude takes precedence
			config: FilesystemMonitorConfig{
				IncludeExt: []string{".data"},
				ExcludeExt: []string{".data"},
			},
			path:         filepath.Join(tempDir, "archive.data"),
			expectedIgnore: true,
		},
		{
			name: "排除规则中使用相对路径组件", // Test case: path with relative components in exclude rule
			config: FilesystemMonitorConfig{
				ExcludePaths: []string{filepath.Join(tempDir, "child", "..", "ignore_me")},
			},
			path:         filepath.Join(tempDir, "ignore_me", "file.txt"),
			expectedIgnore: true,
		},
		{
			name: "空配置 - 不应忽略任何路径", // Test case: empty config - should not ignore
			config: FilesystemMonitorConfig{},
			path:         filepath.Join(tempDir, "some_file.anything"),
			expectedIgnore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 确保未指定的配置字段使用默认值，以免干扰测试结果
			if tt.config.RenameMatchWindow == 0 {
				tt.config.RenameMatchWindow = 2 * time.Second
			}
			if tt.config.RenameCleanupInterval == 0 {
				tt.config.RenameCleanupInterval = 5 * time.Second
			}
			monitor := NewFilesystemMonitor(tt.config)
			assert.Equal(t, tt.expectedIgnore, monitor.shouldIgnore(tt.path))
		})
	}
}

// TestCalculateFileHash 测试calculateFileHash方法的各种场景
func TestCalculateFileHash(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "hash_test") // 为哈希测试创建临时目录
	require.NoError(t, err)
	defer os.RemoveAll(tempDir) // 测试结束后清理

	content := "Hello, EDR! This is a test content for hashing." // 测试文件内容
	testFilePath := filepath.Join(tempDir, "testfile.txt")    // 测试文件路径
	err = ioutil.WriteFile(testFilePath, []byte(content), 0644) // 写入测试文件
	require.NoError(t, err)

	// 预先计算期望的MD5哈希值
	hMd5 := md5.Sum([]byte(content))
	expectedMd5 := fmt.Sprintf("%x", hMd5)

	tests := []struct {
		name          string
		config        FilesystemMonitorConfig
		filePath      string
		setupFile     func(t *testing.T, filePath string, size int64) string // 可选的设置函数，返回实际使用的文件路径
		expectedHash  string                                                    // 期望的哈希值
		expectError   bool                                                      // 是否期望发生错误
	}{
		{
			name: "sha256默认算法", // Test case: sha256 default
			config: FilesystemMonitorConfig{
				CalculateHash: true,
				HashAlgorithm: "sha256", // 明确设置以便清晰，虽然它是默认值
				MaxFileSize:   1024,
			},
			filePath:     testFilePath,
			expectedHash: "5a3d5571d31823c9c83eafd8e3689d2926da6b5709ff0459e2ff7911ff60fea8", // 已修正的sha256sum
		},
		{
			name: "显式指定md5算法", // Test case: md5 explicitly
			config: FilesystemMonitorConfig{
				CalculateHash: true,
				HashAlgorithm: "md5",
				MaxFileSize:   1024,
			},
			filePath:     testFilePath,
			expectedHash: expectedMd5,
		},
		{
			name: "显式指定sha1算法", // Test case: sha1 explicitly
			config: FilesystemMonitorConfig{
				CalculateHash: true,
				HashAlgorithm: "sha1",
				MaxFileSize:   1024,
			},
			filePath:     testFilePath,
			expectedHash: "f1018cc26d11e917498f4fdf866e1afa330705c3", // 已修正的sha1sum
		},
		{
			name: "禁用哈希计算", // Test case: hash calculation disabled
			config: FilesystemMonitorConfig{
				CalculateHash: false,
				MaxFileSize:   1024,
			},
			filePath:     testFilePath,
			expectedHash: "",
		},
		{
			name: "文件过大不计算哈希", // Test case: file too large
			config: FilesystemMonitorConfig{
				CalculateHash: true,
				HashAlgorithm: "md5",
				MaxFileSize:   int64(len(content) - 1), // 设置最大文件大小比实际内容小
			},
			filePath:     testFilePath,
			expectedHash: "",
		},
		{
			name: "空文件不计算哈希", // Test case: empty file
			config: FilesystemMonitorConfig{
				CalculateHash: true,
				HashAlgorithm: "md5",
				MaxFileSize:   1024,
			},
			setupFile: func(t *testing.T, p string, size int64) string {
				emptyFilePath := filepath.Join(tempDir, "empty.txt")
				require.NoError(t, ioutil.WriteFile(emptyFilePath, []byte{}, 0644)) // 创建空文件
				return emptyFilePath
			},
			expectedHash: "",
		},
		{
			name: "目录不计算哈希", // Test case: directory - should not hash
			config: FilesystemMonitorConfig{
				CalculateHash: true,
				HashAlgorithm: "md5",
				MaxFileSize:   1024,
			},
			filePath:     tempDir, // 路径是一个目录
			expectedHash: "",
		},
		{
			name: "不支持的哈希算法", // Test case: unsupported algorithm
			config: FilesystemMonitorConfig{
				CalculateHash: true,
				HashAlgorithm: "sha3-256", // 一个不支持的算法
				MaxFileSize:   1024,
			},
			filePath:    testFilePath,
			expectError: true,
		},
		{
			name: "文件不存在", // Test case: file does not exist
			config: FilesystemMonitorConfig{
				CalculateHash: true,
				MaxFileSize:   1024,
			},
			filePath:    filepath.Join(tempDir, "nonexistent.txt"), // 一个不存在的文件
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 确保未指定的配置字段使用默认值
			if tt.config.RenameMatchWindow == 0 {
				tt.config.RenameMatchWindow = 2 * time.Second
			}
			if tt.config.RenameCleanupInterval == 0 {
				tt.config.RenameCleanupInterval = 5 * time.Second
			}
			monitor := NewFilesystemMonitor(tt.config)
			
			currentFilePath := tt.filePath
			// 重新生成主测试文件，用于相关的哈希测试，以确保内容是原始的
			if tt.name == "sha256默认算法" || tt.name == "显式指定sha1算法" { // 根据中文名称调整
				errWrite := ioutil.WriteFile(testFilePath, []byte(content), 0644)
				require.NoError(t, errWrite, "为测试 '%s' 重写测试文件失败", tt.name)
				currentFilePath = testFilePath
			}

			if tt.setupFile != nil {
				currentFilePath = tt.setupFile(t, tt.filePath, 0) 
			}

			hashVal, err := monitor.calculateFileHash(currentFilePath) // 将变量'hash'重命名为'hashVal'以避免与'hash'包冲突

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedHash, hashVal)
			}
		})
	}
}

// setupTestDirWithFile 是一个辅助函数，用于创建一个包含测试文件的临时目录，供Start/Stop测试使用
func setupTestDirWithFile(t *testing.T) (string, string) {
	t.Helper() // 标记这是一个测试辅助函数
	tempDir, err := ioutil.TempDir("", "fs_monitor_start_stop_test")
	require.NoError(t, err)
	testFile := filepath.Join(tempDir, "initial.txt")
	require.NoError(t, ioutil.WriteFile(testFile, []byte("start"), 0644))
	return tempDir, testFile
}

// TestFilesystemMonitor_Start_Stop 测试文件系统监控器的Start和Stop方法
func TestFilesystemMonitor_Start_Stop(t *testing.T) {
	t.Run("正常启动和停止", func(t *testing.T) {
		tempDir, _ := setupTestDirWithFile(t)
		defer os.RemoveAll(tempDir)

		config := FilesystemMonitorConfig{
			Enabled:    true,
			WatchPaths: []string{tempDir},
			BufferSize: 10,
		}
		monitor := NewFilesystemMonitor(config)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := monitor.Start(ctx)
		assert.NoError(t, err)
		assert.True(t, monitor.running, "调用Start后，监控器应处于运行状态")

		// 等待一小段时间，确保goroutines实际启动
		time.Sleep(100 * time.Millisecond)

		err = monitor.Stop()
		assert.NoError(t, err)
		assert.False(t, monitor.running, "调用Stop后，监控器应处于非运行状态")
	})

	t.Run("在禁用状态下启动", func(t *testing.T) {
		config := FilesystemMonitorConfig{Enabled: false}
		monitor := NewFilesystemMonitor(config)
		ctx := context.Background()
		err := monitor.Start(ctx)
		assert.NoError(t, err)
		assert.False(t, monitor.running, "如果监控器在禁用状态下启动，则不应运行")
	})

	t.Run("重复启动返回错误", func(t *testing.T) {
		tempDir, _ := setupTestDirWithFile(t)
		defer os.RemoveAll(tempDir)

		monitor := NewFilesystemMonitor(FilesystemMonitorConfig{Enabled: true, WatchPaths: []string{tempDir}})
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx)) // 第一次启动
		err := monitor.Start(ctx)               // 第二次启动
		assert.Error(t, err, "第二次调用Start应返回错误")
		require.NoError(t, monitor.Stop())    // 清理
	})

	t.Run("停止未运行的监控器是无操作", func(t *testing.T) {
		monitor := NewFilesystemMonitor(FilesystemMonitorConfig{Enabled: true})
		err := monitor.Stop() // 监控器未启动时调用Stop
		assert.NoError(t, err)
		assert.False(t, monitor.running)
	})
	
	t.Run("使用无效监控路径启动(不存在的路径)", func(t *testing.T) {
		nonExistentPath := filepath.Join(os.TempDir(), "edr_sdk_test_non_existent_dir_12345")
		config := FilesystemMonitorConfig{
			Enabled:    true,
			WatchPaths: []string{nonExistentPath},
		}
		monitor := NewFilesystemMonitor(config)
		ctx := context.Background()
		// 对于不存在的路径，Start可能不会立即返回错误，
		// 因为fsnotify可能会优雅地处理或记录警告。
		//核心测试是它不会panic并且Stop可以正常工作。
		err := monitor.Start(ctx) 
		assert.NoError(t, err) // fsnotify.Add可能失败，Start会捕获它。如果路径在addWatchPaths时确实无效，则会记录并跳过。
		assert.True(t, monitor.running) // 如果所有路径都无效并被跳过，watcher仍可能运行（但不监控任何内容）
		
		// 等待一小段时间，以便处理潜在的错误（如果有）
		time.Sleep(50 * time.Millisecond)
		
		err = monitor.Stop()
		assert.NoError(t, err)
	})
}

// TestEventGenerationAndRenameLogic 是一个更复杂的集成测试，用于模拟文件操作并验证事件生成和重命名逻辑。
func TestEventGenerationAndRenameLogic(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "fs_event_test") // 为事件测试创建临时目录
	require.NoError(t, err)
	defer os.RemoveAll(tempDir) // 测试结束后清理

	config := FilesystemMonitorConfig{
		Enabled:             true,
		WatchPaths:          []string{tempDir},
		RecursiveWatch:      true,
		BufferSize:          100,
		RenameMatchWindow:   500 * time.Millisecond, // 测试时使用较短的窗口以加快速度
		RenameCleanupInterval: 1 * time.Second,      // 测试时使用较快的清理间隔
		CalculateHash:       true,
		MaxFileSize:         1024, // 测试时使用较小的文件大小
	}
	monitor := NewFilesystemMonitor(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // 测试的总体超时时间
	defer cancel()

	require.NoError(t, monitor.Start(ctx))

	eventChan := monitor.GetEventChannel()
	var receivedEvents []FileEvent // 用于存储接收到的事件
	var eventWg sync.WaitGroup     // 用于等待事件收集goroutine完成
	
	eventWg.Add(1)
	go func() { // 启动一个goroutine来收集事件
		defer eventWg.Done()
		for {
			select {
			case event, ok := <-eventChan:
				if !ok {
					t.Log("事件通道已关闭")
					return
				}
				t.Logf("接收到事件: 类型=%s, 路径=%s, 旧路径=%s, 哈希=%s", event.Type, event.Path, event.OldPath, event.Hash)
				receivedEvents = append(receivedEvents, event)
			case <-ctx.Done(): // 如果测试超时或上下文被显式取消
				t.Log("事件收集超时/上下文已完成")
				return
			}
		}
	}()

	// --- 模拟文件操作 ---
	filePath1 := filepath.Join(tempDir, "file1.txt")
	filePath1Renamed := filepath.Join(tempDir, "file1_renamed.txt")
	content1 := "content for file1"
	content1HashExpected, _ := calculateTestHash(content1, "sha256")

	// 1. 创建 file1.txt
	t.Log("正在创建 file1.txt")
	require.NoError(t, ioutil.WriteFile(filePath1, []byte(content1), 0644))
	// 等待足够的时间以确保create事件在rename之前被处理
	time.Sleep(config.RenameMatchWindow + 100*time.Millisecond) 

	// 2. 将 file1.txt 重命名为 file1_renamed.txt
	t.Logf("正在将 %s 重命名为 %s", filePath1, filePath1Renamed)
	require.NoError(t, os.Rename(filePath1, filePath1Renamed))
	// 等待足够的时间以确保rename事件被处理
	time.Sleep(config.RenameMatchWindow + 100*time.Millisecond) 

	// 3. 创建一个目录
	subDir := filepath.Join(tempDir, "subdir")
	t.Logf("正在创建目录 %s", subDir)
	require.NoError(t, os.Mkdir(subDir, 0755))
	time.Sleep(config.RenameMatchWindow / 2) // 目录操作的等待时间可以短一些

	// 4. 在子目录中创建一个文件，该文件将被重命名移出
	fileInSubDir := filepath.Join(subDir, "subfile.dat")
	fileInSubDirRenamedOut := filepath.Join(tempDir, "subfile_moved_out.dat")
	contentSub := "sub dir content"
	t.Logf("正在创建 %s", fileInSubDir)
	require.NoError(t, ioutil.WriteFile(fileInSubDir, []byte(contentSub), 0644))
	time.Sleep(config.RenameMatchWindow + 100*time.Millisecond)

	// 5. 将 subfile.dat 重命名（移动）出子目录
	t.Logf("正在将 %s 重命名为 %s (移出操作)", fileInSubDir, fileInSubDirRenamedOut)
	require.NoError(t, os.Rename(fileInSubDir, fileInSubDirRenamedOut))
	time.Sleep(config.RenameMatchWindow + 100*time.Millisecond)

	// 6. 创建一个将被清理机制移除的文件（模拟悬挂的RENAME）
	fileToBeCleanedUp := filepath.Join(tempDir, "cleanup_target.tmp")
	t.Logf("正在创建 %s (用于重命名清理测试)", fileToBeCleanedUp)
	require.NoError(t, ioutil.WriteFile(fileToBeCleanedUp, []byte("cleanup"), 0644))
	time.Sleep(100 * time.Millisecond)
	// 通过手动添加到pendingRenames来模拟一个RENAME OUT操作
	monitor.pendingRenamesMu.Lock()
	// 使其看起来像一个较早的事件，以便被清理逻辑捕获
	monitor.pendingRenamesFrom[fileToBeCleanedUp] = time.Now().Add(-config.RenameCleanupInterval * 2) 
	monitor.pendingRenamesMu.Unlock()
	t.Logf("已手动将 %s 添加到待处理的重命名列表，用于清理测试", fileToBeCleanedUp)
	// 等待清理逻辑运行
	time.Sleep(config.RenameCleanupInterval + config.RenameMatchWindow) 

	// --- 停止监控并收集事件 ---
	t.Log("正在停止监控器")
	require.NoError(t, monitor.Stop())
	t.Log("正在等待事件收集goroutine完成")
	eventWg.Wait() // 等待事件收集goroutine结束

	// --- 断言 --- 
	// 验证是否收到了预期的事件
	assertCreateEvent(t, receivedEvents, filePath1, false, content1HashExpected)
	assertRenameEvent(t, receivedEvents, filePath1Renamed, filePath1, false, content1HashExpected)
	assertCreateEvent(t, receivedEvents, subDir, true, "") // 目录不计算哈希
	assertCreateEvent(t, receivedEvents, fileInSubDir, false, "") // subfile.dat的哈希值 (移动前)
	assertRenameEvent(t, receivedEvents, fileInSubDirRenamedOut, fileInSubDir, false, "") // subfile_moved_out.dat的哈希值
	
	// 对于清理操作，我们期望收到一个针对fileToBeCleanedUp的REMOVE事件
	// 注意：事件顺序可能无法保证，因此我们在此搜索它。
	foundCleanupRemove := false
	for _, ev := range receivedEvents {
		if ev.Type == "remove" && ev.Path == fileToBeCleanedUp {
			foundCleanupRemove = true
			break
		}
	}
	assert.True(t, foundCleanupRemove, "期望收到一个针对被清理的重命名文件的REMOVE事件: %s", fileToBeCleanedUp)

	t.Logf("总共接收到的事件数量: %d", len(receivedEvents))
}

// assertCreateEvent 是一个辅助函数，用于断言是否存在特定路径的CREATE事件，并校验其属性。
func assertCreateEvent(t *testing.T, events []FileEvent, path string, isDir bool, expectedHash string) {
	t.Helper()
	for _, event := range events {
		if event.Type == "create" && event.Path == path {
			assert.Equal(t, isDir, event.IsDir, "CREATE事件的IsDir属性不匹配: %s", path)
			if !isDir && expectedHash != "" {
				assert.Equal(t, expectedHash, event.Hash, "CREATE事件的哈希值不匹配: %s", path)
			}
			return
		}
	}
	assert.Fail(t, "未找到CREATE事件", "路径: %s", path)
}

// assertRenameEvent 是一个辅助函数，用于断言是否存在特定新旧路径的RENAME事件，并校验其属性。
func assertRenameEvent(t *testing.T, events []FileEvent, newPath, oldPath string, isDir bool, expectedHash string) {
	t.Helper()
	for _, event := range events {
		if event.Type == "rename" && event.Path == newPath && event.OldPath == oldPath {
			assert.Equal(t, isDir, event.IsDir, "RENAME事件的IsDir属性不匹配: %s -> %s", oldPath, newPath)
			if !isDir && expectedHash != "" {
				// 哈希是在重命名后的newPath上计算的
				assert.Equal(t, expectedHash, event.Hash, "RENAME事件的哈希值不匹配: %s -> %s", oldPath, newPath)
			}
			return
		}
	}
	assert.Fail(t, "未找到RENAME事件", "新路径: %s, 旧路径: %s", newPath, oldPath)
}

// calculateTestHash 是一个辅助函数，用于计算测试内容的哈希值
func calculateTestHash(content, algorithm string) (string, error) {
	var h hash.Hash // 使用 hash.Hash 接口
	switch algorithm {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	default:
		return "", fmt.Errorf("测试中不支持的哈希算法: %s", algorithm)
	}
	_ , err := h.Write([]byte(content))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
} 