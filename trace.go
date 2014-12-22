/**
agpl license goes here

author david stainton
**/

package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"fmt"
	"github.com/david415/go-netfilter-queue"
)

type NFQueueTraceroute struct {
	q       *netfilter.NFQueue
	packets <-chan netfilter.NFPacket
	count   int
	ttl     uint8
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

/* XXX todo: Make this "iterator" smarter;
   perhaps increment after repeating a TTL 3 times or so.
*/
func (n *NFQueueTraceroute) currentTTL() uint8 {
	n.ttl += 1
	return n.ttl
}

/* XXX todo: we can fuck with some unknown ratio of packets
for a given flow without brekaing it. Perhaps this can be dynamic based on
packets per second in a given flow?
*/
func (n *NFQueueTraceroute) processPacket(p netfilter.NFPacket) {
	n.count += 1
	if n.count%67 == 0 {
		p.SetModifiedVerdict(netfilter.NF_ACCEPT, serializeWithTTL(p.Packet, n.currentTTL()))
	} else {
		p.SetVerdict(netfilter.NF_ACCEPT)
	}
}

// XXX fixme: make me work with IPv6!
// This function takes a
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

/***
use this rough POC with a iptables nfqueue rule that will select
a tcp flow... like this:
iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --dport 2666

***/
func main() {
	n := NFQueueTraceroute{
		count: 1,
		ttl:   1,
	}
	n.Start()
}
