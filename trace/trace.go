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

// Parasitic Traceroute API -  Forward/Reverse TCP traceroute API which uses Linux Netfilter Queue
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
	// IP TTL is a uint8 and therefore max value is 255
	MAX_TTL uint8 = 255
)

// TcpIpLayer struct is used as a channel type for passing tcp/ip packet data
// from the pcap sniffer to the TCP-session-close goroutine-channel pipeline.
type TcpIpLayer struct {
	ip  layers.IPv4
	tcp layers.TCP
}

func (t *TcpIpLayer) Layers() (layers.IPv4, layers.TCP) {
	return t.ip, t.tcp
}

// PayloadIcmpIpLayer struct is used as a channel type for passing icmp/ip packet data
// from the pcap sniffer to the traceroute-receive-ICMP-reply goroutine-channel pipeline.
type PayloadIcmpIpLayer struct {
	ip      layers.IPv4
	icmp    layers.ICMPv4
	payload gopacket.Payload
}

// NFQueueTraceObserverOptions struct is a helper struct used to encapsulate
// the user tuned parameters for NFQueueTraceObserver struct.
type NFQueueTraceObserverOptions struct {

	// QueueId is the Netfilter Queue we should use
	QueueId int
	// The maximum number of packets the queue is capable of storing
	QueueSize int

	// Iface is a network interface to listen for ICMP-TTL-expired packets and TCP FIN packets
	Iface string

	// TTLMax specifies the highest TTL value to use in the TCP traceroute
	TTLMax uint8
	// TTLRepeatMax specifies the number of times to send a given TTL for the traceroute
	TTLRepeatMax int

	// RepeatMode implies NFQueue verdict NF_REPEAT
	// which means sending a duplicate packet
	RepeatMode bool
	// MangleFreq is the number of packets that should traverse
	// a tracked flow before we mangle a packet's TTL for the traceroute operation
	MangleFreq int
	// TimeoutSeconds is the number of seconds to wait before incrementing the TTL
	// and further mangling packets for a given flow.
	TimeoutSeconds int
}

// NFQueueTraceObserver is a struct used to track concurrents TCP traceroute operations
// in TCP streams it observes in the specified Netfilter Queue.
type NFQueueTraceObserver struct {
	// options is passed in from the user in our constructor NewNFQueueTraceObserver
	options NFQueueTraceObserverOptions
	// nfq is used to talk to the Netfilter Queue
	nfq *netfilter.NFQueue

	// flowTracker helps use identify which traceroute operation a packet belongs to
	flowTracker *FlowTracker

	// packets is a channel for interacting with NFQueue
	packets <-chan netfilter.NFPacket
	// done channel is used to stop all the traceroutes
	done chan bool

	// stopReceiveChan is used to stop the pcap sniffer goroutine
	// used for capturing ICMP replies and TCP FIN packets
	stopReceiveChan chan bool

	// receiveParseChan is written to by the goroutine reading packets off the wire
	receiveParseChan chan []byte
	// receiveTcpChan is written to by the packet parsing goroutine
	receiveTcpChan chan TcpIpLayer
	// receiveIcmpChan is written to by the packet parsing goroutine
	receiveIcmpChan chan PayloadIcmpIpLayer
	// addResultMutex is used to serialize writing traceroute results to the logfile
	addResultMutex sync.Mutex
}

// NewNFQueueTraceObserver creates a NFQueueTraceObserver struct given a NFQueueTraceObserverOptions struct
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

// Start method creates two goroutines.
// 1. read packets from NFQueue and pipeline to traceroute operation
// 2. read packets from pcap sniffer and pipeline
// to process TCP FIN packets and ICMP TTL expired traceroute responses
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

// Stop method is an unfinished work in progress.
// Currently it only stoped the NFQueue packet processing goroutine.
func (o *NFQueueTraceObserver) Stop() {
	log.Print("NFQueueTraceObserver Stop\n")
	o.done <- true
}

// receiveTraceRoute method uses a mutex to serialize writing trace results to a logfile
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

// processPacket method parses packets read from the NFQueue
// and dispatches them to the appropriate traceroute pipeline
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

// startReceivingReplies createa a goroutine to read packets via a pcap sniffer
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

// startParsingReplies starts a goroutine which participates
// in the pcap sniffing pipeline by reading packets from
// it's channel and writing them to an output channel;
// either the TCP or ICMP output channels.
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
	o.startWatchingForTcpClose()

	go func() {
		defer close(o.receiveIcmpChan)
		defer close(o.receiveTcpChan)
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

// startReceivingIcmp creates a goroutine to read ICMP packets
// from it's input channel... determine if the packet is a TTL-expired
// ICMP response from one of our traceroute operations. If so then
// output to that traceroute's channel
func (o *NFQueueTraceObserver) startReceivingIcmp() {
	go func() {
		// bundle is network protocol layer cake payload/icmp/ip
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

			nfqTrace.receiveReplyChan <- bundle.ip.SrcIP
			//nfqTrace.replyReceived(bundle.ip.SrcIP)
		}
	}()
}

// startWatchingForTcpClose receives packets from the pcap
// packet parsing goroutine. We simply consume packets looking
// for a familiar TCP connection. If we see a FIN packet we
// stop the traceroute operation.
func (o *NFQueueTraceObserver) startWatchingForTcpClose() {
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

// String returns a string representation of a HopTick
func (t *HopTick) String() string {
	return fmt.Sprintf("%s %s", t.ip.String(), t.instant.String())
}

// TCPResult uses a hashmap to relate route hop TTLs to TraceTick structs
// this can be used to identify route changes over time
type TcpRoute struct {
	// TTL is the key
	routeMap map[uint8][]HopTick
}

// NewTcpRoute returns a TcpRoute struct
func NewTcpRoute() TcpRoute {
	return TcpRoute{
		routeMap: make(map[uint8][]HopTick, 1),
	}
}

// AddHopTick takes a TTL and HopTick and adds them to a
// hashmap where the TTL is the key.
func (r *TcpRoute) AddHopTick(ttl uint8, hoptick HopTick) {
	r.routeMap[ttl] = append(r.routeMap[ttl], hoptick)
}

// GetRepeatLength returns the number of HopTicks accumulated for a given TTL
func (r *TcpRoute) GetRepeatLength(ttl uint8) int {
	return len(r.routeMap[ttl])
}

// GetSortedKeys returns a slice of sorted keys (TTL) from our routeMap
func (r *TcpRoute) GetSortedKeys() []int {
	var keys []int
	for k := range r.routeMap {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	return keys
}

// String returns a string representation of the thus far accumulated traceroute information
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

// NFQueueTraceroute struct is used to perform traceroute operations
// on a single TCP flow... where flow means a unidirection packet stream.
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

	receiveReplyChan chan net.IP

	stopTimerChannel    chan bool
	restartTimerChannel chan bool
}

// NewNFQueueTraceroute returns a new NFQueueTraceroute struct and starts two goroutines;
// a timer goroutine for determining when to increment the TTL for the traceroute operation...
// and a goroutine to process ICMP-TTL-expired responses.
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
		receiveReplyChan:    make(chan net.IP),
		stopTimerChannel:    make(chan bool),
		restartTimerChannel: make(chan bool),
	}
	nfqTrace.StartResponseTimer()
	nfqTrace.startReceivingReplies()
	return &nfqTrace
}

// StartReponseTimer starts a goroutine to provide a timeout service
// to the traceroute operaton...
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

// submitResult... no comment because this is stupid and needs to go away and die.
func (n *NFQueueTraceroute) submitResult() {
	log.Print(n.observer.receiveTraceRoute(n.id, n.tcpRoute))
}

// Stop stops the timeout goroutine... but it should be further extended to
// shutdown the entire traceroute operation which means dealing with other
// goroutines.
func (n *NFQueueTraceroute) Stop() {
	log.Print("stop traceroute\n")
	n.stopped = true
	n.stopTimerChannel <- true
	close(n.stopTimerChannel)
	close(n.restartTimerChannel)
	n.submitResult()
}

// processPacket receives packets from the NFQueue and decides weather
// or not to mangle the TTL for our tracerouting purposes.
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

// startReceivingReplies starts a goroutine which receives ICMP-TTL-expired replies
// belonging to our TCP traceroute flow.
func (n *NFQueueTraceroute) startReceivingReplies() {
	go func() {
		for replyIP := range n.receiveReplyChan {
			hoptick := HopTick{
				ip:      replyIP,
				instant: time.Now(),
			}
			n.tcpRoute.AddHopTick(n.ttl, hoptick)
			fmt.Printf("TTL %d HopTick %s\n", n.ttl, hoptick.String())

			if n.ttl == n.ttlMax && (n.tcpRoute.GetRepeatLength(n.ttl) >= n.ttlRepeatMax || n.responseTimedOut) {
				n.Stop() // finished!
			}
		}
	}()
}
