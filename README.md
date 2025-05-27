# EDR SDK for Go

[![Go Version](https://img.shields.io/badge/Go-1.24.3-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.linux.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

EDR (Endpoint Detection and Response) SDK for Go - 专为Linux平台设计的端点检测和响应Go语言SDK。

## 🚀 功能特性

### 📊 端点监控 (Endpoint Monitoring)
- **进程监控**: 实时监控进程创建、终止和行为
- **文件系统监控**: 监控文件和目录的创建、修改、删除操作
- **网络连接监控**: 跟踪网络连接和流量
- **系统调用监控**: 监控关键系统调用

### 🛡️ 威胁检测 (Threat Detection)
- **恶意软件检测**: 基于签名和行为的恶意软件识别
- **异常行为分析**: 检测异常的系统和用户行为
- **IOC匹配**: 威胁指标匹配和检测
- **行为模式分析**: 基于机器学习的威胁检测

### 📈 数据收集与分析 (Data Collection & Analysis)
- **系统信息收集**: 收集系统配置和状态信息
- **日志收集**: 统一日志收集和解析
- **事件关联**: 安全事件关联分析
- **取证数据**: 数字取证数据收集

### 🚨 事件响应 (Incident Response)
- **自动化响应**: 可配置的自动响应动作
- **进程控制**: 进程隔离和终止
- **网络隔离**: 网络连接控制
- **文件操作**: 文件隔离和删除

### 🔗 集成接口 (Integration APIs)
- **SIEM集成**: 与SIEM系统的集成接口
- **威胁情报**: 威胁情报平台集成
- **云安全**: 云安全平台集成
- **第三方工具**: 其他安全工具集成

### 📋 报告与可视化 (Reporting)
- **安全事件报告**: 详细的安全事件报告
- **威胁分析报告**: 威胁分析和评估报告
- **合规性报告**: 安全合规性报告

## 🏗️ 架构设计

```
edr-sdk-go/
├── pkg/                    # 公共包
│   ├── monitoring/         # 端点监控模块
│   ├── detection/          # 威胁检测模块
│   ├── collection/         # 数据收集模块
│   ├── response/           # 事件响应模块
│   ├── integration/        # 集成接口模块
│   └── reporting/          # 报告模块
├── internal/               # 内部包
│   ├── config/             # 配置管理
│   ├── logger/             # 日志系统
│   └── utils/              # 工具函数
├── cmd/                    # 命令行工具
│   ├── edr-agent/          # EDR代理
│   └── edr-cli/            # 命令行工具
├── examples/               # 示例代码
├── docs/                   # 文档
├── scripts/                # 脚本
└── test/                   # 测试
```

## 🛠️ 安装

### 前置要求
- Go 1.24.3 或更高版本
- Linux 操作系统
- Root权限 (某些监控功能需要)

### 通过go get安装

```bash
go get github.com/XXXXD-cation/edr-sdk-go
```

### 通过git克隆

```bash
git clone https://github.com/XXXXD-cation/edr-sdk-go.git
cd edr-sdk-go
go build ./cmd/edr-agent
go build ./cmd/edr-cli
```

## 🚀 快速开始

### 基本使用示例

```go
package main

import (
    "context"
    "log"
    
    "github.com/XXXXD-cation/edr-sdk-go/pkg/monitoring"
    "github.com/XXXXD-cation/edr-sdk-go/pkg/detection"
)

func main() {
    ctx := context.Background()
    
    // 创建进程监控器
    procMonitor := monitoring.NewProcessMonitor()
    
    // 创建威胁检测器
    detector := detection.NewThreatDetector()
    
    // 启动监控
    if err := procMonitor.Start(ctx); err != nil {
        log.Fatal(err)
    }
    
    // 启动检测
    if err := detector.Start(ctx); err != nil {
        log.Fatal(err)
    }
    
    // 等待信号...
}
```

## 📚 文档

- [API文档](docs/api.md)
- [配置指南](docs/configuration.md)
- [开发指南](docs/development.md)
- [示例代码](examples/)

## 🤝 贡献

欢迎贡献代码！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详细信息。

## 👨‍💻 作者

- **ccnochch** - *初始开发* - [GitHub](https://github.com/ccnochch)

## 🙏 致谢

感谢所有为这个项目做出贡献的开发者。 