/*
 * nfqTrace.go - Parasitic Forward/Reverse TCP traceroute using Linux Netfilter Queue
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

package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"encoding/binary"
	"flag"
	"github.com/david415/go-netfilter-queue"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	MAX_TTL uint8 = 255
)

var queueId = flag.Int("queue-id", 0, "NFQueue ID number")
var queueSize = flag.Int("queue-size", 10000, "Maximum capacity of the NFQueue")
var logFile = flag.String("log-file", "nfqtrace.log", "log file")
var iface = flag.String("interface", "wlan0", "Interface to get packets from")
var timeoutSeconds = flag.Int("timeout", 30, "Number of seconds to await a ICMP-TTL-expired response")
var ttlMax = flag.Int("maxttl", 30, "Maximum TTL that will be used in the traceroute")
var ttlRepeatMax = flag.Int("ttlrepeat", 3, "Number of times each TTL should be sent")
var mangleFreq = flag.Int("packetfreq", 6, "Number of packets that should traverse a flow before we mangle the TTL")

// this is a composite struct type called "flowKey"
// used to track tcp/ip flows... as a hashmap key.
type flowKey [2]gopacket.Flow

// concurrent-safe hashmap of tcp/ip-flowKeys to NFQueueTraceroute`s
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

func (f *FlowTracker) Delete(flow flowKey) {
	f.lock.Lock()
	delete(f.flowMap, flow)
	f.lock.Unlock()
}

func (f *FlowTracker) GetFlowTrace(flow flowKey) *NFQueueTraceroute {
	f.lock.RLock()
	ret := f.flowMap[flow]
	f.lock.RUnlock()
	return ret
}

type NFQueueTraceObserverOptions struct {
	// network interface to listen for ICMP responses
	queueId   int
	queueSize int

	iface string

	ttlMax       uint8
	ttlRepeatMax int

	mangleFreq     int
	timeoutSeconds int
}

type NFQueueTraceObserver struct {
	// passed in from the user in our constructor...
	options NFQueueTraceObserverOptions

	flowTracker *FlowTracker
	nfq         *netfilter.NFQueue

	// packet channel for interacting with NFQueue
	packets <-chan netfilter.NFPacket

	// this is used to stop all the traceroutes
	done chan bool

	addResultMutex sync.Mutex
}

func NewNFQueueTraceObserver(options NFQueueTraceObserverOptions) *NFQueueTraceObserver {
	var err error
	o := NFQueueTraceObserver{
		options: options,
		done:    make(chan bool),
	}

	flowTracker := NewFlowTracker()
	o.flowTracker = flowTracker
	// XXX adjust these parameters
	o.nfq, err = netfilter.NewNFQueue(uint16(o.options.queueId), uint32(o.options.queueSize), netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		panic(err)
	}
	o.packets = o.nfq.GetPackets()
	return &o
}

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
				// XXX todo: stop other goroutines
				break
			}
		}
	}()
}

func (o *NFQueueTraceObserver) Stop() {
	o.done <- true
}

// log trace results
func (o *NFQueueTraceObserver) receiveTraceResult(traceID flowKey, traceResult map[uint8][]net.IP) {
	o.addResultMutex.Lock()

	ipFlow := traceID[0]
	tcpFlow := traceID[1]
	srcIP, dstIP := ipFlow.Endpoints()
	srcPort, dstPort := tcpFlow.Endpoints()
	log.Printf("start of trace: flow id %s:%s -> %s:%s\n", srcIP, srcPort.String(), dstIP, dstPort.String())

	// XXX sort result TTLs
	var keys []int
	nfqTrace := o.flowTracker.GetFlowTrace(traceID)
	for k := range nfqTrace.traceResult {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	for _, k := range keys {
		log.Printf("ttl: %d\n", k)
		for _, ip := range nfqTrace.traceResult[uint8(k)] {
			log.Printf("ip %s\n", ip.String())
		}
	}

	log.Printf("end of trace: flow id %s:%s -> %s:%s\n", srcIP, srcPort.String(), dstIP, dstPort.String())

	o.addResultMutex.Unlock()
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
		nfqTrace := NewNFQueueTraceroute(flow, o, o.options.ttlMax, o.options.ttlRepeatMax, o.options.mangleFreq, o.options.timeoutSeconds)
		o.flowTracker.AddFlow(flow, nfqTrace)
	}
	nfqTrace := o.flowTracker.GetFlowTrace(flow)
	nfqTrace.processPacket(p)
}

// return a net.IP channel to report all the ICMP reponse SrcIP addresses
// that have the ICMP time exceeded flag set
func (o *NFQueueTraceObserver) startReceivingReplies() {
	snaplen := 65536
	filter := "icmp" // the idea here is to capture only ICMP packets

	var eth layers.Ethernet
	var ip layers.IPv4
	var icmp layers.ICMPv4
	var payload gopacket.Payload
	var flow flowKey

	decoded := make([]gopacket.LayerType, 0, 4)

	handle, err := pcap.OpenLive(o.options.iface, int32(snaplen), true, pcap.BlockForever)
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
			if typ != layers.ICMPv4TypeTimeExceeded {
				continue
			}

			// XXX todo: check that the IP header protocol value is set to TCP
			flow = getPacketFlow(payload)

			// XXX it feels dirty to have the mutex around the hashmap
			// i'm thinking about using channels instead...
			if o.flowTracker.HasFlow(flow) == false {
				// ignore ICMP ttl expire packets that are for flows other than the ones we are currently tracking
				continue
			}

			nfqTrace := o.flowTracker.GetFlowTrace(flow)
			nfqTrace.replyReceived(ip.SrcIP)
		}
	}()
}

type NFQueueTraceroute struct {
	id flowKey

	observer *NFQueueTraceObserver

	ttlMax         uint8
	ttlRepeatMax   int
	mangleFreq     int
	timeoutSeconds int

	ttlRepeat int
	ttl       uint8
	count     int

	// ip.TTL -> list of ip addrs
	traceResult map[uint8][]net.IP

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
func NewNFQueueTraceroute(id flowKey, observer *NFQueueTraceObserver, ttlMax uint8, ttlRepeatMax, mangleFreq, timeoutSeconds int) *NFQueueTraceroute {
	nfqTrace := NFQueueTraceroute{
		id:                  id,
		observer:            observer,
		ttl:                 1,
		ttlMax:              ttlMax,
		ttlRepeat:           1,
		ttlRepeatMax:        ttlRepeatMax,
		mangleFreq:          mangleFreq,
		count:               1,
		traceResult:         make(map[uint8][]net.IP, 1),
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

				if n.ttl >= n.ttlMax && n.ttlRepeat >= n.ttlRepeatMax {
					n.Stop()
					return
				}

				n.responseTimedOut = true
			case <-n.restartTimerChannel:
				continue
			case <-n.stopTimerChannel:
				return
			}
		}
	}()
}

func (n *NFQueueTraceroute) submitResult() {
	n.observer.receiveTraceResult(n.id, n.traceResult)
}

func (n *NFQueueTraceroute) Stop() {
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

	if n.count%n.mangleFreq == 0 {
		n.ttlRepeat += 1

		if n.responseTimedOut {
			n.ttl += 1
			n.ttlRepeat = 0
			n.responseTimedOut = false
			n.restartTimerChannel <- true
		} else if n.ttlRepeat == n.ttlRepeatMax {
			n.ttl += 1
			n.ttlRepeat = 0
			n.responseTimedOut = false
			n.restartTimerChannel <- true
		}

		// terminate trace upon max ttl and ttlRepeatMax conditions
		if n.ttl > n.ttlMax && n.ttlRepeat == (n.ttlRepeatMax-1) {
			n.Stop()
			p.SetVerdict(netfilter.NF_ACCEPT)
			return
		}

		p.SetModifiedVerdict(netfilter.NF_REPEAT, serializeWithTTL(p.Packet, n.ttl))
	} else {
		p.SetVerdict(netfilter.NF_ACCEPT)
	}
	n.count = n.count + 1
}

// XXX
// store the "reply" source ip address (icmp ttl expired packet with payload matching this flow)
func (n *NFQueueTraceroute) replyReceived(ip net.IP) {
	n.traceResult[n.ttl] = append(n.traceResult[n.ttl], ip)
	if n.ttl == n.ttlMax && len(n.traceResult[n.ttl]) >= n.ttlRepeatMax {
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

// We use this to deal with rfc792 implementations where
// the original packet is NOT sent back via ICMP payload but
// instead 64 bits of the original packet are sent.
// https://tools.ietf.org/html/rfc792
// Returns a TCP Flow.
// XXX obviously the 64 bits could be from a UDP packet or something else
// however this is *good-enough* for NFQueue TCP traceroute!
// XXX should we look at the protocol specified in the IP header
// and set it's type here? no we should probably not even get this
// far if the IP header has something other than TCP specified...
func getTCPFlowFromTCPHead(data []byte) gopacket.Flow {
	var srcPort, dstPort layers.TCPPort
	srcPort = layers.TCPPort(binary.BigEndian.Uint16(data[0:2]))
	dstPort = layers.TCPPort(binary.BigEndian.Uint16(data[2:4]))
	// XXX convert to tcp/ip flow
	tcpSrc := layers.NewTCPPortEndpoint(srcPort)
	tcpDst := layers.NewTCPPortEndpoint(dstPort)
	tcpFlow, _ := gopacket.FlowFromEndpoints(tcpSrc, tcpDst)
	// error (^ _) is only non-nil if the two endpoint types don't match
	return tcpFlow
}

// given a byte array packet return a tcp/ip flow
func getPacketFlow(packet []byte) flowKey {
	var ip layers.IPv4
	var tcp layers.TCP
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip, &tcp)
	err := parser.DecodeLayers(packet, &decoded)
	if err != nil {
		// XXX last 64 bits... we only use the last 32 bits
		tcpHead := packet[len(packet)-8 : len(packet)]
		tcpFlow := getTCPFlowFromTCPHead(tcpHead)
		return flowKey{ip.NetworkFlow(), tcpFlow}
	}
	return flowKey{ip.NetworkFlow(), tcp.TransportFlow()}
}

/***
to be used with an iptables nfqueue rule that will select
a tcp flow like this:
iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --dport 2666

or like this:
iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --sport 9000
***/
func main() {

	flag.Parse()

	if *ttlMax > int(MAX_TTL) {
		panic("TTL is a uint8, maximum value is 255")
	}

	f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to create log file: %s\n", err)
	}
	log.SetOutput(f)

	options := NFQueueTraceObserverOptions{
		queueId:        *queueId,
		queueSize:      *queueSize,
		iface:          *iface,
		timeoutSeconds: *timeoutSeconds,
		ttlMax:         uint8(*ttlMax),
		ttlRepeatMax:   *ttlRepeatMax,
		mangleFreq:     *mangleFreq,
	}
	o := NewNFQueueTraceObserver(options)
	o.Start()

	// XXX run forever or until someone hits control-c...
	finished := make(chan bool)
	<-finished
}
