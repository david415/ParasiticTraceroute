/*
 * flow.go - Parasitic Traceroute flow tracking api
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
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"encoding/binary"
	"net"
	"sort"
	"sync"
)

// flowKey is a composite struct type used to track tcp/ip flows...
// as a hashmap key.
// flowKey needs to go away and die... mostly because
// it's a composite struct which doesn't have any methods
// to enforce correct usage... I will therefore replace it
// with a struct with methods.
type flowKey [2]gopacket.Flow

// TcpFlowKey is directional... it matches a specific TCP flow direction.
type TcpFlowKey struct {
	flow [2]gopacket.Flow
}

// NewTcpFlowKey returns a new TcpFlowKey struct
func NewTcpFlowKey(ipFlow gopacket.Flow, tcpFlow gopacket.Flow) TcpFlowKey {
	return TcpFlowKey{
		flow: [2]gopacket.Flow{
			ipFlow,
			tcpFlow,
		},
	}
}

// TcpBidirectionalFlowKey struct can be used as a hashmap key.
// Bidirectional in this case means that each of these keys
// for each TCP connection can be represented by two TcpFlowKey`s
type TcpBidirectionalFlowKey struct {
	flow flowKey
}

// NewTcpBidirectionalFlowKey returns a new TcpBidirectionalFlowKey struct
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

// Get method is XXX probably not useful
func (f *TcpBidirectionalFlowKey) Get() flowKey {
	return f.flow
}

// FlowTracker struct is a concurrent-safe hashmap of tcp/ip-flowKeys to NFQueueTraceroute`s
type FlowTracker struct {
	lock          *sync.RWMutex
	flowMap       map[flowKey]*NFQueueTraceroute
	connectionMap map[TcpBidirectionalFlowKey]*NFQueueTraceroute
}

// NewFlowTracker returns a new FlowTracker struct
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		lock:          new(sync.RWMutex),
		flowMap:       make(map[flowKey]*NFQueueTraceroute),
		connectionMap: make(map[TcpBidirectionalFlowKey]*NFQueueTraceroute),
	}
}

// HasFlow returns true if the specified flowKey is
// a key in our flowMap hashmap.
func (f *FlowTracker) HasFlow(flow flowKey) bool {
	defer f.lock.RUnlock()
	f.lock.RLock()
	_, ok := f.flowMap[flow]
	return ok
}

// HasConnection returns true if the specified TcpBidirectionalFlowKey
// is a key in our connectionMap hashmap.
func (f *FlowTracker) HasConnection(biflow TcpBidirectionalFlowKey) bool {
	defer f.lock.RUnlock()
	f.lock.RLock()
	_, ok := f.connectionMap[biflow]
	return ok
}

// GetConnectionTrace returns the NFQueueTraceroute struct pointer associated with
// a specified TcpBidirectionalFlowKey
func (f *FlowTracker) GetConnectionTrace(flow TcpBidirectionalFlowKey) *NFQueueTraceroute {
	return f.connectionMap[flow]
}

// AddFlow adds a NFQueueTraceroute struct pointer to our bookeeping hashmaps
//XXX needs some cleanup?
func (f *FlowTracker) AddFlow(ip layers.IPv4, tcp layers.TCP, nfqTrace *NFQueueTraceroute) {
	defer f.lock.Unlock()
	f.lock.Lock()
	flow := flowKey{ip.NetworkFlow(), tcp.TransportFlow()}
	f.flowMap[flow] = nfqTrace
	f.connectionMap[NewTcpBidirectionalFlowKey(ip, tcp)] = nfqTrace
}

// Delete... this needs to go away. Not used.
func (f *FlowTracker) Delete(flow flowKey) {
	defer f.lock.Unlock()
	f.lock.Lock()
	delete(f.flowMap, flow)
}

// GetFlowTrace returns a NFQueueTraceroute struct pointer
// given a flowKey
func (f *FlowTracker) GetFlowTrace(flow flowKey) *NFQueueTraceroute {
	defer f.lock.RUnlock()
	f.lock.RLock()
	ret := f.flowMap[flow]
	return ret
}

// getTCPFlowFromTCPHead is used to deal with rfc792 implementations where
// the original outbound packet is NOT sent back via ICMP payload but
// instead 64 bits of the original packet are sent.
// https://tools.ietf.org/html/rfc792
// Returns assumes TCP and returns a gopacket.Flow.
// XXX obviously the 64 bits could be from a UDP packet or something else
// however this is *good-enough* for NFQueue TCP traceroute!
// XXX should perhaps look at the protocol number specified in the IP header
// and set it's type here? I don't have a use-case for that right now.
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

// getPacketFlow returns a tcp/ip flowKey
// given a byte array packet
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

// serializeWithTTL takes a gopacket.Packet and a TTL
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
