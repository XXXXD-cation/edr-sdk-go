package network

import "time"

// EventType 定义网络事件的类型
type EventType string

const (
	EventTypeTCPConnect  EventType = "tcp_connect"
	EventTypeTCPAccept   EventType = "tcp_accept"
	EventTypeTCPClose    EventType = "tcp_close"
	EventTypeUDPSend     EventType = "udp_send"
	EventTypeUDPRecv     EventType = "udp_recv"
	EventTypeDNSQuery    EventType = "dns_query"
	EventTypeDNSResponse EventType = "dns_response" // 或合并到DNSQuery事件中
)

// ProcessContext 包含与事件相关的进程信息
type ProcessContext struct {
	PID             uint32    `json:"pid"`
	Comm            string    `json:"comm"`            // 进程名 (e.g., "curl")
	ExePath         string    `json:"exe_path"`        // 可执行文件完整路径
	Cmdline         string    `json:"cmdline"`         // 命令行参数
	UID             uint32    `json:"uid"`
	GID             uint32    `json:"gid"`
	PPID            uint32    `json:"ppid"`            // 父进程ID
	StartTime       time.Time `json:"start_time"`      // 进程启动时间
	ExecutableHash  string    `json:"executable_hash,omitempty"` // SHA256等
}

// NetworkConnectionInfo 包含通用的网络连接信息
type NetworkConnectionInfo struct {
	LocalAddr    string `json:"local_addr"`
	LocalPort    uint16 `json:"local_port"`
	RemoteAddr   string `json:"remote_addr"`
	RemotePort   uint16 `json:"remote_port"`
	Protocol     string `json:"protocol"` // "TCP", "UDP"
	SAFamily     string `json:"sa_family"`  // "AF_INET", "AF_INET6"
}

// BaseEvent 是所有网络事件的基础结构
type BaseEvent struct {
	Timestamp     time.Time      `json:"timestamp"`
	Type          EventType      `json:"type"`
	ProcessCtx    ProcessContext `json:"process_ctx"`
	Error         string         `json:"error,omitempty"` // 事件处理中发生的错误
}

// TCPEvent 代表TCP连接事件
type TCPEvent struct {
	BaseEvent
	Connection NetworkConnectionInfo `json:"connection"`
	SNI        string                `json:"sni,omitempty"` // Server Name Indication
	BytesSent  uint64                `json:"bytes_sent,omitempty"` // 对于Close事件
	BytesRecv  uint64                `json:"bytes_recv,omitempty"` // 对于Close事件
}

// UDPEvent 代表UDP通信事件的元数据
type UDPEvent struct {
	BaseEvent
	Connection NetworkConnectionInfo `json:"connection"`
	// UDP通常是无连接的，这里Connection代表单次收发的源/目标信息
	// Bytes uint64 `json:"bytes,omitempty"` // 单次收发字节数，可选
}

// DNSEvent 代表DNS查询/响应事件
type DNSEvent struct {
	BaseEvent // ProcessCtx 会是发起DNS查询的进程
	QueryName    string   `json:"query_name"`
	QueryType    string   `json:"query_type"` // "A", "AAAA", "CNAME", etc.
	ResponseCode string   `json:"response_code,omitempty"` // e.g., "NOERROR", "NXDOMAIN"
	ResponseIPs  []string `json:"response_ips,omitempty"` // 解析到的IP地址
	DNSServer    string   `json:"dns_server,omitempty"`   // DNS服务器IP
	// DNSEvent 可以通过UDPEvent的源/目标IP端口（53）来触发其解析和生成
} 