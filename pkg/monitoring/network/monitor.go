package network

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/XXXXD-cation/edr-sdk-go/internal/config"
	// Placeholder for process monitor interface if needed for context
	// "github.com/XXXXD-cation/edr-sdk-go/pkg/monitoring/process"
)

// Monitor orchestrates network event monitoring.
// It loads eBPF programs, manages event channels, and coordinates with other components.
type Monitor struct {
	logger          *zap.Logger
	config          config.NetworkMonitorConfig
	ebpfHandler     *EBPFHandler // Handles eBPF loading, map interaction, etc.
	eventChannel    chan interface{} // Channel to send processed events to the EDR agent core
	// processQuerier ProcessQuerier // Interface to query process context
	bootTimeEpochNs int64
	ctx             context.Context
	cancel          context.CancelFunc
}

// ProcessQuerier defines an interface to get process context information.
// This will be implemented by the process monitoring module or a shared service.
// type ProcessQuerier interface {
// 	GetProcessContext(pid uint32) (ProcessContext, error)
// }

// getBootTimeEpochNs calculates the system boot time in nanoseconds since the Unix epoch.
func getBootTimeEpochNs(logger *zap.Logger) (int64, error) {
	// Read /proc/uptime
	content, err := os.ReadFile("/proc/uptime")
	if err != nil {
		logger.Error("Failed to read /proc/uptime", zap.Error(err))
		return 0, err
	}

	fields := strings.Fields(string(content))
	if len(fields) < 1 {
		errMsg := fmt.Sprintf("invalid format in /proc/uptime: %s", string(content))
		logger.Error(errMsg)
		return 0, fmt.Errorf(errMsg)
	}

	uptimeSecondsFloat, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		logger.Error("Failed to parse uptime from /proc/uptime", zap.String("value", fields[0]), zap.Error(err))
		return 0, err
	}

	nowNs := time.Now().UnixNano()
	uptimeNs := int64(uptimeSecondsFloat * 1e9)
	bootTimeEpochNs := nowNs - uptimeNs

	logger.Debug("Calculated boot time",
		zap.Int64("bootTimeEpochNs", bootTimeEpochNs),
		zap.Time("bootTimeApprox", time.Unix(0, bootTimeEpochNs)),
		zap.Float64("uptimeSeconds", uptimeSecondsFloat),
	)
	return bootTimeEpochNs, nil
}

// NewMonitor creates a new Network Monitor.
func NewMonitor(ctx context.Context, logger *zap.Logger, cfg config.NetworkMonitorConfig, evtChan chan interface{} /*, pq ProcessQuerier*/) (*Monitor, error) {
	logger.Info("Initializing network monitor")

	bootTime, err := getBootTimeEpochNs(logger)
	if err != nil {
		logger.Error("Failed to get system boot time", zap.Error(err))
		return nil, fmt.Errorf("failed to get system boot time: %w", err)
	}

	// Create a new context for this monitor that can be cancelled
	monitorCtx, cancel := context.WithCancel(ctx)

	m := &Monitor{
		logger:          logger.Named("network-monitor"),
		config:          cfg,
		eventChannel:    evtChan,
		// processQuerier:  pq,
		bootTimeEpochNs: bootTime,
		ctx:             monitorCtx,
		cancel:          cancel,
	}

	m.ebpfHandler, err = NewEBPFHandler(m.logger, m.config, m.bootTimeEpochNs)
	if err != nil {
		m.logger.Error("Failed to initialize eBPF handler", zap.Error(err))
		cancel() // ensure context is cancelled if setup fails
		return nil, err
	}

	logger.Info("Network monitor initialized successfully")
	return m, nil
}

// Start begins the network monitoring process.
func (m *Monitor) Start() error {
	if !m.config.Enabled {
		m.logger.Info("Network monitor is disabled by configuration")
		return nil
	}

	m.logger.Info("Starting network monitor")

	err := m.ebpfHandler.Start(m.ctx, m.handleRawEvent) // Pass a callback to handle events from eBPF
	if err != nil {
		m.logger.Error("Failed to start eBPF handler", zap.Error(err))
		return err
	}

	m.logger.Info("Network monitor started successfully")
	return nil
}

// Stop halts the network monitoring process.
func (m *Monitor) Stop() {
	m.logger.Info("Stopping network monitor")
	if m.cancel != nil {
		m.cancel() // Signal goroutines to stop
	}
	if m.ebpfHandler != nil {
		m.ebpfHandler.Stop()
	}
	m.logger.Info("Network monitor stopped")
}

// handleRawEvent is a callback function passed to the EBPFHandler.
// It receives raw event data, enriches it, filters it, and sends it to the event channel.
func (m *Monitor) handleRawEvent(event interface{}) {
	switch evt := event.(type) {
	case *TCPEvent:
		m.logger.Debug("Received TCP connect event from eBPF handler", zap.Any("type", evt.Type), zap.Any("pid", evt.ProcessCtx.PID), zap.Any("comm", evt.ProcessCtx.Comm), zap.Any("s_addr", evt.Connection.LocalAddr), zap.Any("s_port", evt.Connection.LocalPort), zap.Any("d_addr", evt.Connection.RemoteAddr), zap.Any("d_port", evt.Connection.RemotePort), zap.Any("sa_family", evt.Connection.SAFamily))
		m.eventChannel <- evt
	case *UDPEvent:
		m.logger.Debug("Received UDP send event from eBPF handler", zap.Any("type", evt.Type), zap.Any("pid", evt.ProcessCtx.PID), zap.Any("comm", evt.ProcessCtx.Comm), zap.Any("s_addr", evt.Connection.LocalAddr), zap.Any("s_port", evt.Connection.LocalPort), zap.Any("d_addr", evt.Connection.RemoteAddr), zap.Any("d_port", evt.Connection.RemotePort), zap.Any("sa_family", evt.Connection.SAFamily))
		m.eventChannel <- evt
	default:
		m.logger.Warn("Received unknown event type in handleRawEvent", zap.Any("eventData", event))
	}
} 