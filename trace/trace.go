/*
 * trace.go - Parasitic Forward/Reverse TCP traceroute api which uses Linux Netfilter Queue
 * Copyright (c) 2014 David Anthony Stainton
 *
 * The MIT License (MIT)
 * Copyright (c) 2014 David Anthony Stainton
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

package trace

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"fmt"
	"github.com/david415/go-netfilter-queue"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	MAX_TTL uint8 = 255
)

// used as a channel type
type TcpIpLayer struct {
	ip  layers.IPv4
	tcp layers.TCP
}

func (t *TcpIpLayer) Layers() (layers.IPv4, layers.TCP) {
	return t.ip, t.tcp
}

// used as a channel type
type PayloadIcmpIpLayer struct {
	ip      layers.IPv4
	icmp    layers.ICMPv4
	payload gopacket.Payload
}

type NFQueueTraceObserverOptions struct {
	// network interface to listen for ICMP responses
	QueueId   int
	QueueSize int

	Iface string

	TTLMax       uint8
	TTLRepeatMax int

	RepeatMode     bool
	MangleFreq     int
	TimeoutSeconds int
}

type NFQueueTraceObserver struct {
	// passed in from the user in our constructor...
	options NFQueueTraceObserverOptions
	nfq     *netfilter.NFQueue

	flowTracker *FlowTracker

	// packet channel for interacting with NFQueue
	packets <-chan netfilter.NFPacket
	// this is used to stop all the traceroutes
	done chan bool

	stopReceiveChan  chan bool
	receiveParseChan chan []byte
	receiveTcpChan   chan TcpIpLayer
	receiveIcmpChan  chan PayloadIcmpIpLayer

	addResultMutex sync.Mutex
}

func NewNFQueueTraceObserver(options NFQueueTraceObserverOptions) *NFQueueTraceObserver {
	var err error
	o := NFQueueTraceObserver{
		options:          options,
		done:             make(chan bool),
		stopReceiveChan:  make(chan bool),
		receiveParseChan: make(chan []byte),
		receiveTcpChan:   make(chan TcpIpLayer),
		receiveIcmpChan:  make(chan PayloadIcmpIpLayer),
	}

	o.flowTracker = NewFlowTracker()
	// XXX adjust these parameters
	o.nfq, err = netfilter.NewNFQueue(uint16(o.options.QueueId), uint32(o.options.QueueSize), netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		panic(err)
	}
	o.packets = o.nfq.GetPackets()
	return &o
}

func (o *NFQueueTraceObserver) Start() {
	log.Print("NFQueueTraceObserver Start\n")
	o.startReceivingReplies()
	go func() {
		for true {
			select {
			case p := <-o.packets:
				o.processPacket(p)
			case <-o.done:
				o.nfq.Close()
				close(o.done) // XXX necessary?
				// XXX todo: stop other goroutines
				break
			}
		}
	}()
}

func (o *NFQueueTraceObserver) Stop() {
	log.Print("NFQueueTraceObserver Stop\n")
	o.done <- true
}

// log trace results
func (o *NFQueueTraceObserver) receiveTraceRoute(traceID flowKey, route TcpRoute) string {
	defer o.addResultMutex.Unlock()
	o.addResultMutex.Lock()

	ipFlow := traceID[0]
	tcpFlow := traceID[1]
	srcIP, dstIP := ipFlow.Endpoints()
	srcPort, dstPort := tcpFlow.Endpoints()

	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("start of trace: flow id %s:%s -> %s:%s\n", srcIP, srcPort.String(), dstIP, dstPort.String()))
	buffer.WriteString(route.String())
	return buffer.String()
}

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
		nfqTrace := NewNFQueueTraceroute(flow, o.options.RepeatMode, o, o.options.TTLMax, o.options.TTLRepeatMax, o.options.MangleFreq, o.options.TimeoutSeconds)
		o.flowTracker.AddFlow(*ip, *tcp, nfqTrace)
	}
	nfqTrace := o.flowTracker.GetFlowTrace(flow)
	nfqTrace.processPacket(p)
}

func (o *NFQueueTraceObserver) startReceivingReplies() {
	log.Print("startReceivingReplies\n")
	snaplen := 65536
	filter := "icmp or tcp"

	handle, err := pcap.OpenLive(o.options.Iface, int32(snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	o.startParsingReplies()

	go func() {
		for {
			select {
			case <-o.stopReceiveChan:
				return
			default:
				data, _, err := handle.ReadPacketData()
				if err != nil {
					continue
				}
				o.receiveParseChan <- data
			}
		}
	}()
}

func (o *NFQueueTraceObserver) startParsingReplies() {
	var eth layers.Ethernet
	var ip layers.IPv4
	var icmp layers.ICMPv4

	var eth2 layers.Ethernet
	var ip2 layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	icmpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip, &icmp, &payload)
	tcpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth2, &ip2, &tcp)
	decoded := make([]gopacket.LayerType, 0, 4)

	o.startReceivingIcmp()
	o.startReceivingTcp()

	go func() {
		for packet := range o.receiveParseChan {
			err := tcpParser.DecodeLayers(packet, &decoded)
			if err == nil {
				o.receiveTcpChan <- TcpIpLayer{
					ip:  ip2,
					tcp: tcp,
				}
				continue
			}
			err = icmpParser.DecodeLayers(packet, &decoded)
			if err == nil {
				o.receiveIcmpChan <- PayloadIcmpIpLayer{
					ip:      ip,
					icmp:    icmp,
					payload: payload,
				}
			}
		}
	}()
}

func (o *NFQueueTraceObserver) startReceivingIcmp() {
	go func() {
		for bundle := range o.receiveIcmpChan {
			log.Print("icmp packet received\n")
			typ := uint8(bundle.icmp.TypeCode >> 8)
			if typ != layers.ICMPv4TypeTimeExceeded {
				continue
			}
			// XXX todo: check that the IP header protocol value is set to TCP
			flow := getPacketFlow(bundle.payload)
			if o.flowTracker.HasFlow(flow) == false {
				// ignore ICMP ttl expire packets that are for flows other than the ones we are currently tracking
				continue
			}
			nfqTrace := o.flowTracker.GetFlowTrace(flow)
			//nfqTrace.replyChan <- bundle.ip.SrcIP
			nfqTrace.replyReceived(bundle.ip.SrcIP)
		}
	}()
}

func (o *NFQueueTraceObserver) startReceivingTcp() {
	go func() {
		for tcpIpLayer := range o.receiveTcpChan {
			ip, tcp := tcpIpLayer.Layers()
			tcpBiFlowKey := NewTcpBidirectionalFlowKey(ip, tcp)
			if o.flowTracker.HasConnection(tcpBiFlowKey) {
				if tcp.FIN {
					log.Print("receiveTcp FIN detected\n")
					nfqTrace := o.flowTracker.GetConnectionTrace(tcpBiFlowKey)
					nfqTrace.Stop()
				}
			}
		}
	}()
}

// HopTick represents a single route hop at a particular instant
type HopTick struct {
	instant time.Time
	ip      net.IP
}

func (t *HopTick) String() string {
	return fmt.Sprintf("%s %s", t.ip.String(), t.instant.String())
}

// TCPResult uses a hashmap to relate route hop TTLs to TraceTick structs
// this can be used to identify route changes over time
type TcpRoute struct {
	// TTL is the key
	routeMap map[uint8][]HopTick
}

func NewTcpRoute() TcpRoute {
	return TcpRoute{
		routeMap: make(map[uint8][]HopTick, 1),
	}
}

func (r *TcpRoute) AddHopTick(ttl uint8, hoptick HopTick) {
	r.routeMap[ttl] = append(r.routeMap[ttl], hoptick)
}

func (r *TcpRoute) GetRepeatLength(ttl uint8) int {
	return len(r.routeMap[ttl])
}

func (r *TcpRoute) GetSortedKeys() []int {
	var keys []int
	for k := range r.routeMap {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	return keys
}

func (r *TcpRoute) String() string {
	var buffer bytes.Buffer
	hops := r.GetSortedKeys()
	for _, k := range hops {
		buffer.WriteString(fmt.Sprintf("ttl: %d\n", k))
		for _, hopTick := range r.routeMap[uint8(k)] {
			buffer.WriteString(hopTick.String())
			buffer.WriteString("\n")
		}
	}
	return buffer.String()
}

type NFQueueTraceroute struct {
	id         flowKey
	repeatMode bool
	observer   *NFQueueTraceObserver

	ttlMax         uint8 // the user specified maximum TTL for this tcp trace
	ttlRepeatMax   int   // how many times shall we repeat each TTL?
	mangleFreq     int   // mangle packet TTL every mangleFreq number of packets traverse this flow
	timeoutSeconds int

	ttl       uint8 // used to keep track of the TTL we currently send out to trace
	ttlRepeat int   // keeps track of how many duplicate TTLs we've sent
	count     int   // counts the packets in this flow

	tcpRoute TcpRoute // the tcp trace generates this TcpRoute

	stopped          bool
	responseTimedOut bool

	// XXX should it be a pointer instead?
	receivePacketChannel chan netfilter.NFPacket

	resumeTimerChannel  chan bool
	stopTimerChannel    chan bool
	restartTimerChannel chan bool
}

// conduct an nfqueue tcp traceroute;
// - send each TTL out ttlRepeatMax number of times.
// - only mangle a packet's TTL after mangleFreq number
// of packets have traversed the flow
func NewNFQueueTraceroute(id flowKey, repeatMode bool, observer *NFQueueTraceObserver, ttlMax uint8, ttlRepeatMax, mangleFreq, timeoutSeconds int) *NFQueueTraceroute {
	nfqTrace := NFQueueTraceroute{
		id:                  id,
		repeatMode:          repeatMode,
		observer:            observer,
		ttl:                 1,
		ttlMax:              ttlMax,
		ttlRepeat:           1,
		ttlRepeatMax:        ttlRepeatMax,
		mangleFreq:          mangleFreq,
		count:               1,
		tcpRoute:            NewTcpRoute(),
		stopped:             false,
		timeoutSeconds:      timeoutSeconds,
		responseTimedOut:    false,
		stopTimerChannel:    make(chan bool),
		restartTimerChannel: make(chan bool),
	}
	nfqTrace.StartResponseTimer()
	return &nfqTrace
}

func (n *NFQueueTraceroute) StartResponseTimer() {

	go func() {
		for {
			select {
			case <-time.After(time.Duration(n.timeoutSeconds) * time.Second):
				log.Printf("timeout fired - ttl %d\n", n.ttl)
				if n.ttl >= n.ttlMax && n.ttlRepeat >= n.ttlRepeatMax {
					n.Stop()
					return
				}
				n.responseTimedOut = true
			case <-n.restartTimerChannel:
				log.Print("restart timer\n")
				n.responseTimedOut = false
				continue
			case <-n.stopTimerChannel:
				log.Print("stop timer\n")
				return
			}
		}
	}()
}

func (n *NFQueueTraceroute) submitResult() {
	log.Print(n.observer.receiveTraceRoute(n.id, n.tcpRoute))
}

func (n *NFQueueTraceroute) Stop() {
	log.Print("stop traceroute\n")
	n.stopped = true
	n.stopTimerChannel <- true
	close(n.stopTimerChannel)
	close(n.restartTimerChannel)
	n.submitResult()
}

// given a packet we decided weather or not to mangle the TTL
// for our tracerouting purposes.
func (n *NFQueueTraceroute) processPacket(p netfilter.NFPacket) {

	if n.stopped {
		p.SetVerdict(netfilter.NF_ACCEPT)
		return
	}

	if n.ttl > n.ttlMax {
		if n.responseTimedOut {
			n.Stop()
			p.SetVerdict(netfilter.NF_ACCEPT)
			return
		}
	}

	if n.count%n.mangleFreq == 0 {
		if n.ttlRepeat == n.ttlRepeatMax {
			if n.responseTimedOut {
				n.ttl += 1
				n.ttlRepeat = 0
				n.responseTimedOut = false
				n.restartTimerChannel <- true
			}
		}
		if n.ttlRepeat < n.ttlRepeatMax {
			if n.repeatMode {
				p.SetModifiedVerdict(netfilter.NF_REPEAT, serializeWithTTL(p.Packet, n.ttl))
			} else {
				p.SetModifiedVerdict(netfilter.NF_ACCEPT, serializeWithTTL(p.Packet, n.ttl))
			}
			n.ttlRepeat += 1
		} else {
			p.SetVerdict(netfilter.NF_ACCEPT)
		}
	} else {
		p.SetVerdict(netfilter.NF_ACCEPT)
	}
	n.count = n.count + 1
}

// XXX
// store the "reply" source ip address (icmp ttl expired packet with payload matching this flow)
func (n *NFQueueTraceroute) replyReceived(ip net.IP) {

	hoptick := HopTick{
		ip:      ip,
		instant: time.Now(),
	}
	n.tcpRoute.AddHopTick(n.ttl, hoptick)
	fmt.Printf("TTL %d HopTick %s\n", n.ttl, hoptick.String())

	if n.ttl == n.ttlMax && (n.tcpRoute.GetRepeatLength(n.ttl) >= n.ttlRepeatMax || n.responseTimedOut) {
		n.Stop() // finished!
	}
}

// This function takes a gopacket.Packet and a TTL
// and returns a byte array of the serialized packet with the specified TTL
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
