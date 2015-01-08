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
	"github.com/david415/HoneyBadger"
	"sync"
)

// FlowTracker struct is a concurrent-safe hashmap of tcp/ip-flowKeys to NFQueueTraceroute`s
type FlowTracker struct {
	lock          *sync.RWMutex
	flowMap       map[HoneyBadger.TcpIpFlow]*NFQueueTraceroute
	connectionMap map[HoneyBadger.TcpBidirectionalFlow]*NFQueueTraceroute
}

// NewFlowTracker returns a new FlowTracker struct
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		lock:          new(sync.RWMutex),
		flowMap:       make(map[HoneyBadger.TcpIpFlow]*NFQueueTraceroute),
		connectionMap: make(map[HoneyBadger.TcpBidirectionalFlow]*NFQueueTraceroute),
	}
}

// HasFlow returns true if the specified flowKey is
// a key in our flowMap hashmap.
func (f *FlowTracker) HasFlow(flow HoneyBadger.TcpIpFlow) bool {
	f.lock.RLock()
	defer f.lock.RUnlock()
	_, ok := f.flowMap[flow]
	return ok
}

// HasConnection returns true if the specified TcpBidirectionalFlowKey
// is a key in our connectionMap hashmap.
func (f *FlowTracker) HasConnection(biflow HoneyBadger.TcpBidirectionalFlow) bool {
	f.lock.RLock()
	defer f.lock.RUnlock()
	_, ok := f.connectionMap[biflow]
	return ok
}

// GetConnectionTrace returns the NFQueueTraceroute struct pointer associated with
// a specified TcpBidirectionalFlowKey
func (f *FlowTracker) GetConnectionTrace(flow HoneyBadger.TcpBidirectionalFlow) *NFQueueTraceroute {
	return f.connectionMap[flow]
}

// AddFlow adds a NFQueueTraceroute struct pointer to our bookeeping hashmaps
//XXX needs some cleanup?
func (f *FlowTracker) AddFlow(flow HoneyBadger.TcpIpFlow, nfqTrace *NFQueueTraceroute) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.flowMap[flow] = nfqTrace
	f.connectionMap[HoneyBadger.NewTcpBidirectionalFlowFromTcpIpFlow(flow)] = nfqTrace
}

// Delete removes the hashmap keys of the item.
// We have two hashmaps; one for flows and one
// for connections (bidirectional flows)...
func (f *FlowTracker) Delete(flow HoneyBadger.TcpIpFlow) {
	f.lock.Lock()
	defer f.lock.Unlock()
	delete(f.flowMap, flow)
	connFlow := HoneyBadger.NewTcpBidirectionalFlowFromTcpIpFlow(flow)
	delete(f.connectionMap, connFlow)
}

// GetFlowTrace returns a NFQueueTraceroute struct pointer
// given a flowKey
//func (f *FlowTracker) GetFlowTrace(flow TcpIpFlow) *NFQueueTraceroute {
func (f *FlowTracker) GetFlow(flow HoneyBadger.TcpIpFlow) *NFQueueTraceroute {
	f.lock.RLock()
	defer f.lock.RUnlock()
	ret := f.flowMap[flow]
	return ret
}

// GetTCPFlowFromTCPHead is used to deal with rfc792 implementations where
// the original outbound packet is NOT sent back via ICMP payload but
// instead 64 bits of the original packet are sent.
// https://tools.ietf.org/html/rfc792
// Returns assumes TCP and returns a gopacket.Flow.
// XXX obviously the 64 bits could be from a UDP packet or something else
// however this is *good-enough* for NFQueue TCP traceroute!
// XXX should perhaps look at the protocol number specified in the IP header
// and set it's type here? I don't have a use-case for that right now.
func GetTCPFlowFromTCPHead(data []byte) gopacket.Flow {
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

// SerializeWithTTL takes a gopacket.Packet (containing a TCP/IP layers) and a TTL
// and returns a byte array of the serialized packet with the specified TTL
func SerializeWithTTL(p gopacket.Packet, ttl uint8) []byte {
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
