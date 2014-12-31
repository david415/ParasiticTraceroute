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
	"flag"
	"fmt"
	"github.com/david415/ParasiticTraceroute/trace"
	"log"
	"net"
	"time"
)

var listenIp = flag.String("listen-ip", "", "IP address of interface to listen on")
var listenTcpPort = flag.Int("listen-port", 0, "TCP port to listen on")

var repeatMode = flag.Bool("repeatMode", false, "repeatMode implies sending an additional packet instead of mangling the existing packet")
var queueId = flag.Int("queue-id", 0, "NFQueue ID number")
var queueSize = flag.Int("queue-size", 10000, "Maximum capacity of the NFQueue")
var logFile = flag.String("log-file", "nfqtrace.log", "log file")
var iface = flag.String("interface", "wlan0", "Interface to get packets from")
var timeoutSeconds = flag.Int("timeout", 3, "Number of seconds to await a ICMP-TTL-expired response")
var ttlMax = flag.Int("maxttl", 30, "Maximum TTL that will be used in the traceroute")
var ttlRepeatMax = flag.Int("ttlrepeat", 2, "Number of times each TTL should be sent")
var mangleFreq = flag.Int("packetfreq", 6, "Number of packets that should traverse a flow before we mangle the TTL")

type NfqTraceServerOptions struct {
	nfqTraceOptions trace.NFQueueTraceObserverOptions
	listenIP        string
	listenTcpPort   uint32 // XXX or change it to type TCPPort?
	RouteLogger     trace.RouteLogger
}

type NfqTraceServer struct {
	options  NfqTraceServerOptions
	listener net.Listener
	hopChan  chan trace.HopTick
}

func NewNfqTraceServer(options NfqTraceServerOptions) NfqTraceServer {
	traceServer := NfqTraceServer{
		options: options,
		hopChan: make(chan trace.HopTick),
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
		// XXX needs rate limiting and or other minimal DOS mitigation
		go n.traceroute(conn)
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

func (n *NfqTraceServer) traceroute(conn net.Conn) {

	log.Printf("traceroute local tcp listen addr %s\n", conn.LocalAddr().String())
	log.Printf("traceroute local tcp listen addr %s\n", conn.RemoteAddr().String())

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
			case hop := <-n.hopChan:
				conn.Write([]byte(hop.String()))
			}
		}
	}()

}

func main() {

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
