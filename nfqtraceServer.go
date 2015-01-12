/*
 * nfqtraceServer.go - netfilter queue traceroute server
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

// nfqueue traceroute server - so netfilter, much tracerouting, wow
package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"flag"
	"fmt"
	"github.com/david415/HoneyBadger"
	"github.com/david415/ParasiticTraceroute/trace"
	"log"
	"net"
	"time"
)

type NfqTraceServerOptions struct {
	nfqTraceOptions trace.NFQueueTraceObserverOptions
	listenIP        string
	listenTcpPort   uint32 // XXX or change it to type TCPPort?
	RouteLogger     trace.RouteLogger
}

type NfqTraceServer struct {
	options  NfqTraceServerOptions
	listener net.Listener
}

func NewNfqTraceServer(options NfqTraceServerOptions) NfqTraceServer {
	traceServer := NfqTraceServer{
		options: options,
	}
	return traceServer
}

func (n *NfqTraceServer) StartListening() {
	log.Printf("Start\n")

	routeLogger := trace.NewServerRouteLogger(n.hopChan)
	n.options.RouteLogger = &routeLogger
	o := trace.NewNFQueueTraceObserver(n.options.nfqTraceOptions)
	o.Start()

	tcpaddr, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", n.options.listenIP, n.options.listenTcpPort))
	if err != nil {
		log.Print(err)
		return
	}
	n.listener, err = net.ListenTCP("tcp4", tcpaddr)
	if err != nil {
		log.Print(err)
		return
	}
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			log.Printf("accept err %s\n", err)
			continue
		}

		log.Printf("%s -> %s\n", conn.LocalAddr().String(), conn.RemoteAddr().String())

		srcTcpAddr, err := net.ResolveTCPAddr(conn.LocalAddr().Network(), conn.LocalAddr().String())
		if err != nil {
			panic(err)
		}

		dstTcpAddr, err := net.ResolveTCPAddr(conn.RemoteAddr().Network(), conn.RemoteAddr().String())
		if err != nil {
			panic(err)
		}

		ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(srcTcpAddr.IP), layers.NewIPEndpoint(dstTcpAddr.IP))
		tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(srcTcpAddr.Port)), layers.NewTCPPortEndpoint(layers.TCPPort(dstTcpAddr.Port)))
		tcpIpFlow := HoneyBadger.NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
		subscribChan := o.Subscribe(tcpIpFlow)

		// XXX needs rate limiting and or other minimal DOS mitigation?
		go n.traceroute(conn, subscribeChan)
	}
	return
}

func (n *NfqTraceServer) sendPeriodicNoise(stop chan bool, out chan []byte) {
	for {
		select {
		case <-time.After(time.Duration(1) * time.Second):
			// XXX appropriate sleep duration should be an argument?
			out <- []byte("noise")
		case <-stop:
			return
		}
	}
}

func (n *NfqTraceServer) traceroute(conn net.Conn, subscribeChan chan trace.HopTick) {

	noiseChan := make(chan []byte)
	stopTrace := make(chan bool)
	stop := make(chan bool)
	go n.sendPeriodicNoise(stop, noiseChan)
	go func() {
		for {
			select {
			case <-stopTrace:
				return
			case noise := <-noiseChan:
				conn.Write(noise)
			case hop := <-subscribeChan:
				conn.Write([]byte(hop.String()))
			}
		}
	}()

}

func main() {

	var (
		listenIp       = flag.String("listen-ip", "", "IP address of interface to listen on")
		listenTcpPort  = flag.Int("listen-port", 0, "TCP port to listen on")
		repeatMode     = flag.Bool("repeatMode", false, "repeatMode implies sending an additional packet instead of mangling the existing packet")
		queueId        = flag.Int("queue-id", 0, "NFQueue ID number")
		queueSize      = flag.Int("queue-size", 10000, "Maximum capacity of the NFQueue")
		iface          = flag.String("interface", "wlan0", "Interface to get packets from")
		timeoutSeconds = flag.Int("timeout", 3, "Number of seconds to await a ICMP-TTL-expired response")
		ttlMax         = flag.Int("maxttl", 30, "Maximum TTL that will be used in the traceroute")
		ttlRepeatMax   = flag.Int("ttlrepeat", 2, "Number of times each TTL should be sent")
		mangleFreq     = flag.Int("packetfreq", 6, "Number of packets that should traverse a flow before we mangle the TTL")
	)

	flag.Parse()

	serverOptions := NfqTraceServerOptions{
		nfqTraceOptions: trace.NFQueueTraceObserverOptions{
			RepeatMode:     *repeatMode,
			QueueId:        *queueId,
			QueueSize:      *queueSize,
			Iface:          *iface,
			TimeoutSeconds: *timeoutSeconds,
			TTLMax:         uint8(*ttlMax),
			TTLRepeatMax:   *ttlRepeatMax,
			MangleFreq:     *mangleFreq,
		},
		listenIP:      *listenIp,
		listenTcpPort: uint32(*listenTcpPort),
	}
	traceServer := NewNfqTraceServer(serverOptions)
	traceServer.StartListening()

	// XXX replace with code that cleans up on control-c
	finished := make(chan bool)
	<-finished
}
