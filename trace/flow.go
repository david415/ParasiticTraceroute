package trace

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"net"
	"sort"
	"sync"
)

// this is a composite struct type called "flowKey"
// used to track tcp/ip flows... as a hashmap key.
type flowKey [2]gopacket.Flow

// this is directional... it matches a specific TCP flow direction.
type TcpFlowKey struct {
	flow [2]gopacket.Flow
}

func NewTcpFlowKey(ipFlow gopacket.Flow, tcpFlow gopacket.Flow) TcpFlowKey {
	return TcpFlowKey{
		flow: [2]gopacket.Flow{
			ipFlow,
			tcpFlow,
		},
	}
}

// bidirectional in this case means that each of these keys
// for each TCP connection can be represented by two TcpFlowKey`s
type TcpBidirectionalFlowKey struct {
	flow flowKey
}

func NewTcpBidirectionalFlowKey(ip layers.IPv4, tcp layers.TCP) TcpBidirectionalFlowKey {
	var tcpSrc gopacket.Endpoint
	var tcpDst gopacket.Endpoint

	//XXX todo: avoid converting to string for sorting!
	IPstr := []string{ip.SrcIP.String(), ip.DstIP.String()}
	sort.Strings(IPstr)
	srcIP := net.ParseIP(IPstr[0])
	dstIP := net.ParseIP(IPstr[1])
	ipSrcEnd := layers.NewIPEndpoint(srcIP)
	ipDstEnd := layers.NewIPEndpoint(dstIP)
	ipFlow, _ := gopacket.FlowFromEndpoints(ipSrcEnd, ipDstEnd)

	if tcp.SrcPort >= tcp.DstPort {
		tcpSrc = layers.NewTCPPortEndpoint(tcp.SrcPort)
		tcpDst = layers.NewTCPPortEndpoint(tcp.DstPort)
	} else {
		tcpSrc = layers.NewTCPPortEndpoint(tcp.DstPort)
		tcpDst = layers.NewTCPPortEndpoint(tcp.SrcPort)
	}
	tcpFlow, _ := gopacket.FlowFromEndpoints(tcpSrc, tcpDst)

	return TcpBidirectionalFlowKey{
		flow: flowKey{ipFlow, tcpFlow},
	}
}

// XXX probably not useful
func (f *TcpBidirectionalFlowKey) Get() flowKey {
	return f.flow
}

// concurrent-safe hashmap of tcp/ip-flowKeys to NFQueueTraceroute`s
type FlowTracker struct {
	lock          *sync.RWMutex
	flowMap       map[flowKey]*NFQueueTraceroute
	connectionMap map[TcpBidirectionalFlowKey]*NFQueueTraceroute
}

func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		lock:          new(sync.RWMutex),
		flowMap:       make(map[flowKey]*NFQueueTraceroute),
		connectionMap: make(map[TcpBidirectionalFlowKey]*NFQueueTraceroute),
	}
}

func (f *FlowTracker) HasFlow(flow flowKey) bool {
	defer f.lock.RUnlock()
	f.lock.RLock()
	_, ok := f.flowMap[flow]
	return ok
}

func (f *FlowTracker) HasConnection(biflow TcpBidirectionalFlowKey) bool {
	defer f.lock.RUnlock()
	f.lock.RLock()
	_, ok := f.connectionMap[biflow]
	return ok
}

func (f *FlowTracker) GetConnectionTrace(flow TcpBidirectionalFlowKey) *NFQueueTraceroute {
	return f.connectionMap[flow]
}

//XXX needs some cleanup
func (f *FlowTracker) AddFlow(ip layers.IPv4, tcp layers.TCP, nfqTrace *NFQueueTraceroute) {
	defer f.lock.Unlock()
	f.lock.Lock()
	flow := flowKey{ip.NetworkFlow(), tcp.TransportFlow()}
	f.flowMap[flow] = nfqTrace
	f.connectionMap[NewTcpBidirectionalFlowKey(ip, tcp)] = nfqTrace
}

func (f *FlowTracker) Delete(flow flowKey) {
	defer f.lock.Unlock()
	f.lock.Lock()
	delete(f.flowMap, flow)
}

func (f *FlowTracker) GetFlowTrace(flow flowKey) *NFQueueTraceroute {
	defer f.lock.RUnlock()
	f.lock.RLock()
	ret := f.flowMap[flow]
	return ret
}
