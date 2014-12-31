/*
 * routeLoggers.go - facilities for logging nfq traceroutes
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
	"fmt"
	"log"
	"sort"
)

type RouteLogger interface {
	AddHopTick(ttl uint8, hop HopTick)
	GetRepeatLength(ttl uint8) int
	Complete()
}

// LogfileRouteLogger uses a hashmap to relate route hop TTLs to TraceTick structs
// this can be used to identify route changes over time
type LogfileRouteLogger struct {
	// TTL is the key
	routeMap map[uint8][]HopTick
	verbose  bool
	hopChan  chan HopTick
}

// NewLogfileRouteLogger returns a LogfileRouteLogger struct
// with accompanying method implements the RouteLogger interface
func NewLogfileRouteLogger(verbose bool) LogfileRouteLogger {
	return LogfileRouteLogger{
		routeMap: make(map[uint8][]HopTick, 1),
		verbose:  verbose,
	}
}

//func (r *LogfileRouteLogger) SetHopChan(hopChan chan HopTick) {
//	r.hopChan = hopChan
//}

// AddHopTick takes a TTL and HopTick and adds them to a
// hashmap where the TTL is the key.
func (r *LogfileRouteLogger) AddHopTick(ttl uint8, hoptick HopTick) {
	r.routeMap[ttl] = append(r.routeMap[ttl], hoptick)
	if r.verbose {
		log.Printf("TTL %d HopTick %s\n", ttl, hoptick.String())
	}
}

// GetRepeatLength returns the number of HopTicks accumulated for a given TTL
func (r *LogfileRouteLogger) GetRepeatLength(ttl uint8) int {
	return len(r.routeMap[ttl])
}

// GetSortedKeys returns a slice of sorted keys (TTL) from our routeMap
func (r *LogfileRouteLogger) GetSortedKeys() []int {
	var keys []int
	for k := range r.routeMap {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	return keys
}

// String returns a string representation of the thus far accumulated traceroute information
func (r *LogfileRouteLogger) String() string {
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

func (r *LogfileRouteLogger) Complete() {
	log.Print(r.String())
}

type ServerRouteLogger struct {
	// TTL is the key
	routeMap map[uint8][]HopTick
	HopChan  chan HopTick
}

func NewServerRouteLogger(hopChan chan HopTick) ServerRouteLogger {
	return ServerRouteLogger{
		routeMap: make(map[uint8][]HopTick, 1),
		HopChan:  hopChan,
	}
}

func (r *ServerRouteLogger) AddHopTick(ttl uint8, hoptick HopTick) {
	log.Print("AddHopTick\n")
	r.routeMap[ttl] = append(r.routeMap[ttl], hoptick)
	r.HopChan <- hoptick
}

// GetRepeatLength returns the number of HopTicks accumulated for a given TTL
func (r *ServerRouteLogger) GetRepeatLength(ttl uint8) int {
	return len(r.routeMap[ttl])
}

// GetSortedKeys returns a slice of sorted keys (TTL) from our routeMap
func (r *ServerRouteLogger) GetSortedKeys() []int {
	var keys []int
	for k := range r.routeMap {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	return keys
}

// String returns a string representation of the thus far accumulated traceroute information
func (r *ServerRouteLogger) String() string {
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

func (r *ServerRouteLogger) Complete() {
	log.Print(r.String())
}
