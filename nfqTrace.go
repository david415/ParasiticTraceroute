/**
agpl license goes here

author david stainton
**/

package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"github.com/david415/go-netfilter-queue"
	"log"
	"net"
)

type flowKey [2]gopacket.Flow

type NFQueueTraceObserver struct {
	packets        <-chan netfilter.NFPacket
	done           chan bool
	ipResponseChan <-chan net.IP
	ResultsChan    chan net.IP
	targetIP       net.IP
	iface          string
	nfq            *netfilter.NFQueue
	decoded        []gopacket.LayerType
	ip4            layers.IPv4
	tcp            layers.TCP
	parser         *gopacket.DecodingLayerParser
	flow           flowKey
	hasFlow        bool
	nfqTrace       NFQueueTraceroute
	ttlRepeatMax   int
	mangleFreq     int
}

func NewNFQueueTraceObserver(iface string, ttlRepeatMax, mangleFreq int) NFQueueTraceObserver {
	var err error
	o := NFQueueTraceObserver{
		hasFlow:      false,
		iface:        iface,
		ResultsChan:  make(chan net.IP),
		done:         make(chan bool),
		decoded:      make([]gopacket.LayerType, 0, 4),
		ttlRepeatMax: ttlRepeatMax,
		mangleFreq:   mangleFreq,
	}
	// XXX adjust these parameters
	o.nfq, err = netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		panic(err)
	}
	o.packets = o.nfq.GetPackets()
	return o
}

// XXX todo: make it compatible with IPv6!
func (o *NFQueueTraceObserver) Start() {
	o.ipResponseChan = getICMPReponseChan(o.iface)
	go o.processResponses()

	o.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &o.ip4, &o.tcp)
	go func() {
		for true {
			select {
			case p := <-o.packets:
				o.processPacket(p)
			case <-o.done:
				close(o.done)
				break
			}
		}
	}()
}

func (o *NFQueueTraceObserver) Stop() {
	o.done <- true
	o.nfq.Close()
}

func (o *NFQueueTraceObserver) processResponses() {
	var ip net.IP
	for true {
		ip = <-o.ipResponseChan
		if ip.Equal(o.targetIP) {
			o.Stop()
		} else {
			o.ResultsChan <- ip
		}
	}
}

// XXX todo: make it compatible with IPv6!
func (o *NFQueueTraceObserver) processPacket(p netfilter.NFPacket) {
	key := flowKey{o.ip4.NetworkFlow(), o.tcp.TransportFlow()}
	if o.hasFlow == false {
		o.hasFlow = true
		o.flow = key
		o.targetIP = o.ip4.DstIP
		o.nfqTrace = NewNFQueueTraceroute(o.ttlRepeatMax, o.mangleFreq)
	} else {
		if key != o.flow {
			// ignore the other flows
			p.SetVerdict(netfilter.NF_ACCEPT)
			return
		}
	}
	o.nfqTrace.processPacket(p)
}

type NFQueueTraceroute struct {
	ttl          uint8
	ttlRepeat    int
	ttlRepeatMax int
	mangleFreq   int
	count        int
}

// conduct an nfqueue tcp traceroute;
// - send each TTL out ttlRepeatMax number of times.
// - only mangle a packet's TTL after mangleFreq number
// of packets have traversed the flow
func NewNFQueueTraceroute(ttlRepeatMax, mangleFreq int) NFQueueTraceroute {
	var nfqTrace = NFQueueTraceroute{}
	nfqTrace.mangleFreq = mangleFreq
	nfqTrace.ttlRepeatMax = ttlRepeatMax
	nfqTrace.ttlRepeat = 1
	nfqTrace.ttl = 1
	nfqTrace.count = 1
	return nfqTrace
}

// return the next TTL which shall be used to conduct a traceroute
// each TTL is used n.ttlRepeatMax number of times.
func (n *NFQueueTraceroute) nextTTL() uint8 {
	n.ttlRepeat += 1
	if n.ttlRepeat >= n.ttlRepeatMax {
		n.ttl += 1
		n.ttlRepeat = 0
	}
	return n.ttl
}

// given a packet we decided weather or not to mangle the TTL
// for our tracerouting purposes. we mangle a packet's TTL only
// after we've seen mangleFreq number of packets traverse the flow.
func (n *NFQueueTraceroute) processPacket(p netfilter.NFPacket) {
	n.count += 1
	if n.count%n.mangleFreq == 0 {
		p.SetModifiedVerdict(netfilter.NF_ACCEPT, serializeWithTTL(p.Packet, n.nextTTL()))
	} else {
		p.SetVerdict(netfilter.NF_ACCEPT)
	}
}

// XXX fixme: make me work with IPv6!
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

// return a net.IP channel to report all the ICMP reponse SrcIP addresses
// that have the ICMP time exceeded flag set
func getICMPReponseChan(iface string) <-chan net.IP {
	snaplen := 65536
	filter := "icmp" // the idea here is to capture only ICMP packets

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var icmp layers.ICMPv4
	var payload gopacket.Payload

	ipChan := make(chan net.IP)
	decoded := make([]gopacket.LayerType, 0, 4)

	handle, err := pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal("error opening pcap handle: ", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &icmp, &payload)

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
			if typ == layers.ICMPv4TypeTimeExceeded {
				ipChan <- ip4.SrcIP
			}
		}
	}()
	return ipChan
}

/***
use this rough POC with a iptables nfqueue rule that will select
a tcp flow... like this:
iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --dport 2666

***/
func main() {
	o := NewNFQueueTraceObserver("wlan0", 3, 66)
	o.Start()

	for true {
		ip := <-o.ResultsChan
		log.Printf("%s\n", ip.String())
	}
	// XXX
}
