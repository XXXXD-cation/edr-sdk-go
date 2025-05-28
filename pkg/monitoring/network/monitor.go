package network

import (
	"context"

	"go.uber.org/zap"

	"github.com/XXXXD-cation/edr-sdk-go/internal/config"
	// Placeholder for process monitor interface if needed for context
	// "github.com/XXXXD-cation/edr-sdk-go/pkg/monitoring/process"
)

// Monitor orchestrates network event monitoring.
// It loads eBPF programs, manages event channels, and coordinates with other components.
type Monitor struct {
	logger         *zap.Logger
	config         config.NetworkMonitorConfig
	ebpfHandler    *EBPFHandler // Handles eBPF loading, map interaction, etc.
	eventChannel   chan interface{} // Channel to send processed events to the EDR agent core
	// processQuerier ProcessQuerier // Interface to query process context
	ctx            context.Context
	cancel         context.CancelFunc
}

// ProcessQuerier defines an interface to get process context information.
// This will be implemented by the process monitoring module or a shared service.
// type ProcessQuerier interface {
// 	GetProcessContext(pid uint32) (ProcessContext, error)
// }

// NewMonitor creates a new Network Monitor.
func NewMonitor(ctx context.Context, logger *zap.Logger, cfg config.NetworkMonitorConfig, evtChan chan interface{} /*, pq ProcessQuerier*/) (*Monitor, error) {
	logger.Info("Initializing network monitor")

	// Create a new context for this monitor that can be cancelled
	monitorCtx, cancel := context.WithCancel(ctx)

	m := &Monitor{
		logger:         logger.Named("network-monitor"),
		config:         cfg,
		eventChannel:   evtChan,
		// processQuerier: pq,
		ctx:            monitorCtx,
		cancel:         cancel,
	}

	var err error
	m.ebpfHandler, err = NewEBPFHandler(m.logger, m.config) // Placeholder for NewEBPFHandler
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
func (m *Monitor) handleRawEvent(eventData interface{}) {
	// Type assert the event data to its concrete type
	switch event := eventData.(type) {
	case *TCPEvent:
		m.logger.Debug("Received TCP connect event from eBPF handler",
			zap.String("type", string(event.Type)),
			zap.Uint32("pid", event.ProcessCtx.PID),
			zap.String("comm", event.ProcessCtx.Comm),
			zap.String("s_addr", event.Connection.LocalAddr),
			zap.Uint16("s_port", event.Connection.LocalPort),
			zap.String("d_addr", event.Connection.RemoteAddr),
			zap.Uint16("d_port", event.Connection.RemotePort),
			zap.String("sa_family", event.Connection.SAFamily),
		)

		// TODO: Enrich event with full process context using m.processQuerier
		// Example: fullCtx, err := m.processQuerier.GetProcessContext(event.ProcessCtx.PID)
		// if err == nil {
		//    event.ProcessCtx = fullCtx
		// } else {
		//    m.logger.Warn("Failed to get full process context", zap.Uint32("pid", event.ProcessCtx.PID), zap.Error(err))
		// }

		// TODO: Apply filters based on m.config
		// if shouldFilter(event, m.config) {
		// 	 m.logger.Debug("Event filtered", zap.Any("event", event))
		// 	 return
		// }

		// Send the processed event to the main event channel
		select {
		case m.eventChannel <- event:
			m.logger.Debug("Sent TCPEvent to main channel")
		case <-m.ctx.Done():
			m.logger.Info("Context done, not sending event to main channel")
			return
		default:
			// This case can happen if the eventChannel is full. 
			// Consider how to handle this: drop, log, or block.
			m.logger.Warn("Main event channel is full, dropping TCPEvent", zap.Uint32("pid", event.ProcessCtx.PID))
		}

	// case *UDPEvent:
	// 	 // Handle UDP events similarly
	// 	 m.logger.Debug("Received UDP event", zap.Any("event", event))
	// 	 // ... enrichment, filtering, sending ...
	// 	 m.eventChannel <- event

	// case *DNSEvent:
	// 	 // Handle DNS events similarly
	// 	 m.logger.Debug("Received DNS event", zap.Any("event", event))
	// 	 // ... enrichment, filtering, sending ...
	// 	 m.eventChannel <- event

	default:
		m.logger.Warn("Received unknown event type in handleRawEvent", zap.Any("eventData", eventData))
	}
} 