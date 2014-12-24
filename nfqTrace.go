/**
agpl license goes here

author david stainton
**/

package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"github.com/david415/go-netfilter-queue"
	"log"
	"net"
	"sync"
)

type flowKey [2]gopacket.Flow

type FlowTracker struct {
	lock    *sync.RWMutex
	flowMap map[flowKey]*NFQueueTraceroute
}

func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		lock:    new(sync.RWMutex),
		flowMap: make(map[flowKey]*NFQueueTraceroute),
	}
}

func (f *FlowTracker) HasFlow(flow flowKey) bool {
	f.lock.RLock()
	_, ok := f.flowMap[flow]
	f.lock.RUnlock()
	return ok
}

func (f *FlowTracker) AddFlow(flow flowKey, nfqTrace *NFQueueTraceroute) {
	f.lock.Lock()
	f.flowMap[flow] = nfqTrace
	f.lock.Unlock()
}

func (f *FlowTracker) GetFlow(flow flowKey) *NFQueueTraceroute {
	f.lock.RLock()
	ret := f.flowMap[flow]
	f.lock.RUnlock()
	return ret
}

type NFQueueTraceObserver struct {
	flowTracker *FlowTracker
	nfq         *netfilter.NFQueue

	// packet channel for interacting with NFQueue
	packets <-chan netfilter.NFPacket

	// this is used to stop all the traceroutes
	done chan bool

	// signal our calling party that we are finished
	// XXX get rid of this?
	finished chan bool

	// network interface to listen for ICMP responses
	iface string

	// these get passed to NFQueueTraceroute
	ttlRepeatMax int
	mangleFreq   int
}

func NewNFQueueTraceObserver(iface string, ttlRepeatMax, mangleFreq int) *NFQueueTraceObserver {
	var err error
	o := NFQueueTraceObserver{
		iface:        iface,
		done:         make(chan bool),
		finished:     make(chan bool),
		ttlRepeatMax: ttlRepeatMax,
		mangleFreq:   mangleFreq,
	}

	flowTracker := NewFlowTracker()
	o.flowTracker = flowTracker
	// XXX adjust these parameters
	o.nfq, err = netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		panic(err)
	}
	o.packets = o.nfq.GetPackets()
	return &o
}

// XXX todo: make it compatible with IPv6!
func (o *NFQueueTraceObserver) Start() {
	o.startReceivingReplies()
	go func() {
		for true {
			select {
			case p := <-o.packets:
				o.processPacket(p)
			case <-o.done:
				o.nfq.Close()
				close(o.done) // XXX necessary?
				break
			}
		}
	}()
}

func (o *NFQueueTraceObserver) Stop() {
	o.done <- true
}

// XXX todo: make it compatible with IPv6!
// XXX make the locking more efficient?
func (o *NFQueueTraceObserver) processPacket(p netfilter.NFPacket) {
	ipLayer := p.Packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := p.Packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		// ignore non-tcp/ip packets
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	flow := flowKey{ip.NetworkFlow(), tcp.TransportFlow()}
	if o.flowTracker.HasFlow(flow) == false {
		nfqTrace := NewNFQueueTraceroute(o.ttlRepeatMax, o.mangleFreq)
		o.flowTracker.AddFlow(flow, nfqTrace)
	}
	nfqTrace := o.flowTracker.GetFlow(flow)
	nfqTrace.processPacket(p)
}

// return a net.IP channel to report all the ICMP reponse SrcIP addresses
// that have the ICMP time exceeded flag set
// XXX fixme: make me compatible with ipv6
func (o *NFQueueTraceObserver) startReceivingReplies() {
	snaplen := 65536
	filter := "icmp" // the idea here is to capture only ICMP packets

	var eth layers.Ethernet
	var ip layers.IPv4
	var icmp layers.ICMPv4
	var payload gopacket.Payload
	var flow flowKey

	decoded := make([]gopacket.LayerType, 0, 4)

	handle, err := pcap.OpenLive(o.iface, int32(snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &icmp, &payload)

	go func() {
		for true {
			data, _, err := handle.ReadPacketData()
			if err != nil {
				continue
			}
			err = parser.DecodeLayers(data, &decoded)
			if err != nil {
				continue
			}
			typ := uint8(icmp.TypeCode >> 8)
			if typ == layers.ICMPv4TypeTimeExceeded {
				flow, err = getPacketFlow(payload)
				if err != nil {
					continue // ignore payloads we fail to parse
				}
				if o.flowTracker.HasFlow(flow) == false {
					// ignore ICMP ttl expire packets that are for flows other than the ones we are currently tracking
					continue
				}
				nfqTrace := o.flowTracker.GetFlow(flow)
				finished := nfqTrace.replyReceived(ip.SrcIP, ip.TTL)

				if finished {
					log.Print("Finished.\n")
					break
				}
			}
		}
	}()
}

type NFQueueTraceroute struct {
	ttl          uint8
	ttlRepeat    int
	ttlRepeatMax int
	mangleFreq   int
	count        int
	traceResult  map[uint8][]net.IP // ip.TTL -> list of ip addrs
}

// conduct an nfqueue tcp traceroute;
// - send each TTL out ttlRepeatMax number of times.
// - only mangle a packet's TTL after mangleFreq number
// of packets have traversed the flow
func NewNFQueueTraceroute(ttlRepeatMax, mangleFreq int) *NFQueueTraceroute {
	return &NFQueueTraceroute{
		ttl:          1,
		ttlRepeat:    1,
		ttlRepeatMax: ttlRepeatMax,
		mangleFreq:   mangleFreq,
		count:        1,
		traceResult:  make(map[uint8][]net.IP, 1),
	}
}

// return the next TTL which shall be used to conduct a traceroute
// each TTL is used n.ttlRepeatMax number of times.
func (n *NFQueueTraceroute) nextTTL() uint8 {
	n.ttlRepeat += 1
	if n.ttlRepeat >= n.ttlRepeatMax {
		n.ttl += 1
		n.ttlRepeat = 0
	}
	return n.ttl
}

// given a packet we decided weather or not to mangle the TTL
// for our tracerouting purposes. we mangle a packet's TTL only
// after we've seen mangleFreq number of packets traverse the flow.
func (n *NFQueueTraceroute) processPacket(p netfilter.NFPacket) {
	if n.count%n.mangleFreq == 0 {
		// repeat means we send out a duplicate packet
		p.SetModifiedVerdict(netfilter.NF_REPEAT, serializeWithTTL(p.Packet, n.nextTTL()))
	} else {
		p.SetVerdict(netfilter.NF_ACCEPT)
	}
	n.count = n.count + 1
}

// process the "reply" (icmp ttl expired packet with payload matching this flow)
// and return true if the trace is "complete"
// XXX how to detect trace-completed condition?
func (n *NFQueueTraceroute) replyReceived(ip net.IP, ttl uint8) bool {
	finished := false
	n.traceResult[ttl] = append(n.traceResult[ttl], ip)
	log.Printf("ttl %d ip %s\n", ttl, ip.String())
	// XXX
	return finished
}

// This function takes a gopacket.Packet and a TTL
// and returns a byte array of the serialized packet with the specified TTL
// XXX fixme: make me work with IPv6!
func serializeWithTTL(p gopacket.Packet, ttl uint8) []byte {
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)
	ip.TTL = ttl
	tcp, _ := tcpLayer.(*layers.TCP)
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	rawPacketBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(rawPacketBuf, opts, ip, tcp); err != nil {
		return nil
	}
	return rawPacketBuf.Bytes()
}

// given a byte array packet return a tcp/ip flow
func getPacketFlow(packet []byte) (flowKey, error) {
	var ip layers.IPv4
	var tcp layers.TCP
	var flow flowKey
	//decoded := make([]gopacket.LayerType, 0, 4)
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &tcp)
	err := parser.DecodeLayers(packet, &decoded)
	if err != nil {
		return flow, err
	}
	flow = flowKey{ip.NetworkFlow(), tcp.TransportFlow()}
	return flow, nil
}

/***
use this rough POC with an iptables nfqueue rule that will select
a tcp flow direction like this:
iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --dport 2666

***/
func main() {
	o := NewNFQueueTraceObserver("wlan0", 3, 66)
	o.Start()
	<-o.finished
	// XXX
}
