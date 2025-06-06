package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"

	"github.com/XXXXD-cation/edr-sdk-go/internal/config"
)

// rawNetworkEventData mirrors the C struct network_event_data_t for parsing ring buffer data.
// Ensure field order and types match the C struct precisely for binary.Read to work.
// C struct reference (from network_bpf.c):
// typedef struct {
//     u64 timestamp_ns;
//     u32 pid;
//     u32 tgid;
//     u32 uid;
//     u32 gid;
//     char comm[16]; // TASK_COMM_LEN
//     event_type_t type; // Underlying type assumed to be u32/int32
//     u16 sport;
//     u16 dport;
//     u8  saddr_v6[16];
//     u8  daddr_v6[16];
//     u8  family;
//     u8  protocol;
// } network_event_data_t;
type rawNetworkEventData struct {
	TimestampNs uint64
	Pid         uint32
	Tgid        uint32
	Uid         uint32
	Gid         uint32
	Comm        [16]int8 // char in C is int8 in Go for signed chars, or uint8 for unsigned.
	                   // TASK_COMM_LEN is 16. Strings from kernel usually null-terminated.
	Type        uint32   // C enum event_type_t will be treated as its underlying integer type (e.g., u32).
	Sport       uint16   // Port is u16 in C, network byte order.
	Dport       uint16   // Port is u16 in C, network byte order.
	SaddrV6     [16]uint8 // IP addresses are byte arrays.
	DaddrV6     [16]uint8
	Family      uint8    // Address family (AF_INET, AF_INET6).
	Protocol    uint8    // IP Protocol (IPPROTO_TCP, IPPROTO_UDP).
	// Padding might be implicitly handled by Go or C struct packing.
	// For direct memory reads like this, exact layout match is critical.
	// We assume standard packing for now.
}

// C enum event_type_t values, manually defined in Go.
// These must match the C definitions in bpf_src/network_bpf.c
const (
	eventTypeUnknown      uint32 = 0 // Corresponds to EVENT_UNKNOWN
	eventTypeTCPConnectV4 uint32 = 1 // Corresponds to EVENT_TCP_CONNECT_V4
	eventTypeTCPConnectV6 uint32 = 2 // Corresponds to EVENT_TCP_CONNECT_V6
	eventTypeUDPSendV4    uint32 = 3 // Corresponds to EVENT_UDP_SEND_V4
	eventTypeUDPSendV6    uint32 = 4 // Corresponds to EVENT_UDP_SEND_V6
	// Add other event types here as they are defined in C and handled.
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package network -cc clang -cflags "-O2 -g -Wall -Werror -target bpfel -D__TARGET_ARCH_x86" network_bpf bpf_src/network_bpf.c -- -Iheaders

// EBPFHandler manages the eBPF lifecycle for network monitoring.
// It loads, attaches, and detaches eBPF programs, and reads events from maps.
type EBPFHandler struct {
	logger          *zap.Logger
	config          config.NetworkMonitorConfig
	bpfObjs         *network_bpfObjects // Corrected case: network_bpfObjects
	links           []link.Link         // To keep track of attached kprobes/tracepoints for cleanup
	ringbufReader   *ringbuf.Reader
	bootTimeEpochNs int64             // Nanoseconds from Unix epoch to system boot time
	stopChan        chan struct{}       // To signal the event processing goroutine to stop
}

// NewEBPFHandler creates a new EBPFHandler.
func NewEBPFHandler(logger *zap.Logger, cfg config.NetworkMonitorConfig, bootTimeNs int64) (*EBPFHandler, error) {
	logger.Info("Initializing eBPF handler for network monitor")

	h := &EBPFHandler{
		logger:          logger.Named("ebpf-handler"),
		config:          cfg,
		bootTimeEpochNs: bootTimeNs,
		stopChan:        make(chan struct{}),
	}

	if err := h.loadAndAttachBPF(); err != nil {
		return nil, fmt.Errorf("failed to load and attach BPF programs: %w", err)
	}

	logger.Info("eBPF handler initialized successfully")
	return h, nil
}

func (h *EBPFHandler) loadAndAttachBPF() error {
	// Remove rlimit memory lock for BPF programs
	if err := rlimit.RemoveMemlock(); err != nil {
		h.logger.Error("Failed to remove memlock rlimit", zap.Error(err))
		return err
	}

	// Load pre-compiled BPF programs and maps into the kernel.
	objs := network_bpfObjects{} // Corrected case: network_bpfObjects
	if err := loadNetwork_bpfObjects(&objs, nil); err != nil { // Corrected case: loadNetwork_bpfObjects
		h.logger.Error("Failed to load bpf objects", zap.Error(err))
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	h.bpfObjs = &objs

	// Attach kprobe for tcp_v4_connect
	l4, err := link.Kprobe("tcp_v4_connect", h.bpfObjs.KprobeTcpV4Connect, nil) 
	if err != nil {
		h.logger.Error("Failed to attach kprobe to tcp_v4_connect", zap.Error(err))
		return fmt.Errorf("attaching tcp_v4_connect kprobe: %w", err)
	}
	h.links = append(h.links, l4)
	h.logger.Info("Attached kprobe to tcp_v4_connect")

	// Attach kretprobe for tcp_v4_connect
	kret4, err := link.Kretprobe("tcp_v4_connect", h.bpfObjs.KretprobeTcpV4ConnectExit, nil)
	if err != nil {
		h.logger.Error("Failed to attach kretprobe to tcp_v4_connect", zap.Error(err))
		l4.Close() // Clean up previous link
		return fmt.Errorf("attaching tcp_v4_connect kretprobe: %w", err)
	}
	h.links = append(h.links, kret4)
	h.logger.Info("Attached kretprobe to tcp_v4_connect")


	// Attach kprobe for tcp_v6_connect
	l6, err := link.Kprobe("tcp_v6_connect", h.bpfObjs.KprobeTcpV6Connect, nil) 
	if err != nil {
		h.logger.Error("Failed to attach kprobe to tcp_v6_connect", zap.Error(err))
		l4.Close(); kret4.Close() // Clean up previous links
		return fmt.Errorf("attaching tcp_v6_connect kprobe: %w", err)
	}
	h.links = append(h.links, l6)
	h.logger.Info("Attached kprobe to tcp_v6_connect")

	// Attach kretprobe for tcp_v6_connect
	kret6, err := link.Kretprobe("tcp_v6_connect", h.bpfObjs.KretprobeTcpV6ConnectExit, nil)
	if err != nil {
		h.logger.Error("Failed to attach kretprobe to tcp_v6_connect", zap.Error(err))
		l4.Close(); kret4.Close(); l6.Close() // Clean up previous links
		return fmt.Errorf("attaching tcp_v6_connect kretprobe: %w", err)
	}
	h.links = append(h.links, kret6)
	h.logger.Info("Attached kretprobe to tcp_v6_connect")

	// Attach kprobe for udp_sendmsg
	ludp4, err := link.Kprobe("udp_sendmsg", h.bpfObjs.KprobeUdpSendmsg, nil)
	if err != nil {
		h.logger.Error("Failed to attach kprobe to udp_sendmsg", zap.Error(err))
		// Consider a more robust cleanup strategy for partial failures
		h.cleanupLinks() // cleanup all previous links
		return fmt.Errorf("attaching udp_sendmsg kprobe: %w", err)
	}
	h.links = append(h.links, ludp4)
	h.logger.Info("Attached kprobe to udp_sendmsg")

	// Attach kprobe for udpv6_sendmsg
	ludp6, err := link.Kprobe("udpv6_sendmsg", h.bpfObjs.KprobeUdpv6Sendmsg, nil)
	if err != nil {
		h.logger.Error("Failed to attach kprobe to udpv6_sendmsg", zap.Error(err))
		h.cleanupLinks()
		return fmt.Errorf("attaching udpv6_sendmsg kprobe: %w", err)
	}
	h.links = append(h.links, ludp6)
	h.logger.Info("Attached kprobe to udpv6_sendmsg")

	// Initialize Ring Buffer reader for the 'events' map
	rd, err := ringbuf.NewReader(h.bpfObjs.Events) // Corrected: use new variable name 'rd'
	if err != nil {
		h.logger.Error("Failed to create ringbuf reader for events map", zap.Error(err))
		h.cleanupLinks() // Use the helper function to clean up all accumulated links
		return fmt.Errorf("creating ringbuf reader for events map: %w", err)
	}
	h.ringbufReader = rd // Assign to struct field after successful creation

	h.logger.Info("BPF programs loaded and attached successfully")
	return nil
}

// Start begins reading events from the eBPF maps.
// It expects a callback function to handle the events.
func (h *EBPFHandler) Start(ctx context.Context, eventCallback func(event interface{})) error {
	h.logger.Info("Starting eBPF event listener")

	go func() {
		for {
			select {
			case <-ctx.Done():
				h.logger.Info("eBPF event listener context done, stopping.")
				return
			default:
				record, err := h.ringbufReader.Read()
				if err != nil {
					if err == ringbuf.ErrClosed {
						h.logger.Info("Ringbuf reader closed, stopping event listening.")
						return
					}
					h.logger.Warn("Error reading from ringbuf", zap.Error(err))
					continue
				}

				// Parse record.RawSample into our manually defined Go struct.
				var rawEvent rawNetworkEventData 
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &rawEvent); err != nil {
					h.logger.Warn("Failed to decode raw event data from BPF", zap.Error(err), zap.Int("sample_size", len(record.RawSample)))
					continue
				}

				// Convert rawEvent to one of our types.go event types
				parsedEvent := h.convertBpfEventToTypedEvent(&rawEvent)
				if parsedEvent == nil {
					h.logger.Debug("BPF event type not handled or unknown", zap.Uint32("rawEventType", rawEvent.Type))
					continue
				}
				eventCallback(parsedEvent)
			}
		}
	}()

	h.logger.Info("eBPF event listener started")
	return nil
}

// convertBpfEventToTypedEvent converts the raw BPF event data to a structured event type.
func (h *EBPFHandler) convertBpfEventToTypedEvent(rawEvent *rawNetworkEventData) interface{} {
	// Convert [16]int8 to string for Comm field
	commBytes := make([]byte, len(rawEvent.Comm))
	for i, c := range rawEvent.Comm {
		if c == 0 { // Null terminator
			commBytes = commBytes[:i]
			break
		}
		commBytes[i] = byte(c)
	}

	// Adjust the timestamp using bootTimeEpochNs
	absoluteTsNs := h.bootTimeEpochNs + int64(rawEvent.TimestampNs)
	eventTimestamp := time.Unix(0, absoluteTsNs)

	baseEvt := BaseEvent{
		Timestamp: eventTimestamp, // Use the corrected, absolute timestamp
		ProcessCtx: ProcessContext{
			PID:  rawEvent.Pid,
			Comm: string(commBytes),
			UID:  rawEvent.Uid,
			GID:  rawEvent.Gid,
			// PPID, ExePath, Cmdline, StartTime, ExecutableHash would be populated by a process enricher later
		},
	}

	connInfo := NetworkConnectionInfo{
		LocalPort:  binary.BigEndian.Uint16(uint16ToBytes(rawEvent.Sport)),
		LocalAddr:  net.IP(rawEvent.SaddrV6[:]).String(),
		RemotePort: binary.BigEndian.Uint16(uint16ToBytes(rawEvent.Dport)),
		RemoteAddr: net.IP(rawEvent.DaddrV6[:]).String(),
	}

	switch rawEvent.Family {
	case 2: // AF_INET defined as 2 in C code
		connInfo.SAFamily = "AF_INET"
		// For IPv4-mapped IPv6, net.IP.To4() will return a non-nil IPv4 address
		if ip4 := net.IP(rawEvent.SaddrV6[:]).To4(); ip4 != nil {
			connInfo.LocalAddr = ip4.String()
		} else {
			connInfo.LocalAddr = net.IP(rawEvent.SaddrV6[:]).String() // Should be 0.0.0.0 if it's truly an IPv4 mapped one that's all zeros before the map part
		}
		if ip4 := net.IP(rawEvent.DaddrV6[:]).To4(); ip4 != nil {
			connInfo.RemoteAddr = ip4.String()
		} else {
			connInfo.RemoteAddr = net.IP(rawEvent.DaddrV6[:]).String()
		}
	case 10: // AF_INET6 defined as 10 in C code
		connInfo.SAFamily = "AF_INET6"
		// For IPv6, we use the full address directly.
		connInfo.LocalAddr = net.IP(rawEvent.SaddrV6[:]).String()
		connInfo.RemoteAddr = net.IP(rawEvent.DaddrV6[:]).String()
	default:
		connInfo.SAFamily = "UNKNOWN"
	}

	switch rawEvent.Protocol {
	case 6: // IPPROTO_TCP defined as 6
		connInfo.Protocol = "TCP"
	case 17: // IPPROTO_UDP defined as 17
		connInfo.Protocol = "UDP"
	default:
		connInfo.Protocol = fmt.Sprintf("Unknown (%d)", rawEvent.Protocol)
	}

	// Determine the event type based on rawEvent.Type
	switch rawEvent.Type {
	case eventTypeTCPConnectV4, eventTypeTCPConnectV6:
		baseEvt.Type = EventTypeTCPConnect
		tcpEvent := &TCPEvent{
			BaseEvent:  baseEvt,
			Connection: connInfo,
		}
		// Further TCP specific enrichment (like SNI) would happen later if applicable.
		return tcpEvent
	case eventTypeUDPSendV4, eventTypeUDPSendV6:
		baseEvt.Type = EventTypeUDPSend
		udpEvent := &UDPEvent{
			BaseEvent:  baseEvt,
			Connection: connInfo,
		}
		return udpEvent
	// Add cases for other event types (TCPAccept, TCPClose, UDPRecv, etc.) here.
	default:
		h.logger.Warn("Unknown or unhandled BPF event type", zap.Uint32("rawEventType", rawEvent.Type))
		return nil
	}
}

// uint16ToBytes converts a uint16 to a 2-byte slice in big endian.
// Helper for port conversion if binary.Read is not used directly on ports.
func uint16ToBytes(u uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, u)
	return b
}

// Stop closes and detaches eBPF programs and maps.
func (h *EBPFHandler) Stop() {
	h.logger.Info("Stopping eBPF handler")
	if h.ringbufReader != nil {
		h.ringbufReader.Close()
		h.logger.Info("Closed ringbuf reader")
	}

	for _, l := range h.links {
		if err := l.Close(); err != nil {
			h.logger.Warn("Failed to close eBPF link", zap.Error(err))
		}
	}
	h.links = nil
	h.logger.Info("Closed and detached eBPF links")

	if h.bpfObjs != nil {
		if err := h.bpfObjs.Close(); err != nil { // .Close() is a method on network_bpfObjects
			h.logger.Warn("Failed to close BPF objects", zap.Error(err))
		}
		h.logger.Info("Closed BPF objects")
	}
	h.logger.Info("eBPF handler stopped")
}

// cleanupLinks is a helper function to clean up all links in case of partial failure
func (h *EBPFHandler) cleanupLinks() {
	for _, l := range h.links {
		if err := l.Close(); err != nil {
			h.logger.Warn("Failed to close eBPF link", zap.Error(err))
		}
	}
	h.links = nil
} 