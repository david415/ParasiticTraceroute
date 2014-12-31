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
	"flag"
	"github.com/david415/ParasiticTraceroute/trace"
	"log"
	"os"
)

const (
	MAX_TTL uint8 = 255
)

var verboseLog = flag.Bool("verboseLog", true, "Output route hops to log before traceroute is complete?")
var repeatMode = flag.Bool("repeatMode", false, "repeatMode implies sending an additional packet instead of mangling the existing packet")
var queueId = flag.Int("queue-id", 0, "NFQueue ID number")
var queueSize = flag.Int("queue-size", 10000, "Maximum capacity of the NFQueue")
var logFile = flag.String("log-file", "nfqtrace.log", "log file")
var iface = flag.String("interface", "wlan0", "Interface to get packets from")
var timeoutSeconds = flag.Int("timeout", 1, "Number of seconds to await a ICMP-TTL-expired response")
var ttlMax = flag.Int("maxttl", 30, "Maximum TTL that will be used in the traceroute")
var ttlRepeatMax = flag.Int("ttlrepeat", 2, "Number of times each TTL should be sent")
var mangleFreq = flag.Int("packetfreq", 6, "Number of packets that should traverse a flow before we mangle the TTL")

/***
to be used with an iptables nfqueue rule that will select
a tcp flow like this:
iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --dport 2666

or like this:
iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --sport 9000
***/
func main() {

	flag.Parse()
	f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to create log file: %s\n", err)
	}
	log.SetOutput(f)

	routeLogger := trace.NewLogfileRouteLogger(*verboseLog)
	options := trace.NFQueueTraceObserverOptions{
		RepeatMode:     *repeatMode,
		QueueId:        *queueId,
		QueueSize:      *queueSize,
		Iface:          *iface,
		TimeoutSeconds: *timeoutSeconds,
		TTLMax:         uint8(*ttlMax),
		TTLRepeatMax:   *ttlRepeatMax,
		MangleFreq:     *mangleFreq,
		RouteLogger:    &routeLogger,
	}

	o := trace.NewNFQueueTraceObserver(options)
	o.Start()

	// XXX replace with code that cleans up on control-c
	finished := make(chan bool)
	<-finished
}
