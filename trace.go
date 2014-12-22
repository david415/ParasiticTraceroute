/**
agpl license goes here

author david stainton
**/

package main

import (
	//	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"fmt"
	"github.com/david415/go-netfilter-queue"
)

type NFQueueTraceroute struct {
	q       *netfilter.NFQueue
	packets <-chan netfilter.NFPacket
	count   int
	done    chan bool
}

func (n *NFQueueTraceroute) Start() {
	var err error
	// XXX adjust these parameters
	n.q, err = netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		panic(err)
	}
	n.done = make(chan bool)
	n.packets = n.q.GetPackets()
	for true {
		select {
		case p := <-n.packets:
			n.processPacket(p)
		case <-n.done:
			//close(n.packets)
			close(n.done)
			break
		}
	}
}

func (n *NFQueueTraceroute) Stop() {
	n.done <- true
	n.q.Close()
}

func (n *NFQueueTraceroute) processPacket(p netfilter.NFPacket) {
	netLayer := p.Packet.Layer(layers.LayerTypeIPv4)
	if netLayer == nil {
		netLayer = p.Packet.Layer(layers.LayerTypeIPv6)
	}
	if netLayer == nil {
		panic("wtf")
	}

	tcpLayer := p.Packet.Layer(layers.LayerTypeTCP)

	if tcpLayer == nil {
		p.SetVerdict(netfilter.NF_ACCEPT)
		return
	}

	ip, _ := netLayer.(*layers.IPv4) // XXX fix me
	tcp, _ := tcpLayer.(*layers.TCP)

	ip.TTL = 1
	fmt.Printf("tcp/ip packet ttl %d tcp.DstPort %d\n", ip.TTL, tcp.DstPort)
	p.SetVerdict(netfilter.NF_ACCEPT)
}

/***
use this rough POC with a iptables nfqueue rule that will select
a tcp flow... like this:
iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --dport 2666

***/
func main() {
	n := NFQueueTraceroute{
		count: 1000,
	}
	n.Start()
}
