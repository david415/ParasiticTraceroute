

=====================================
nfqtrace library and commandline tool
=====================================

abstract
--------
The nfqTrace program performs TCP traceroutes on outgoing streams
wheather they be from a TCP client or server. The Linux Netfilter
Queue facility is used to man-in-the-middle TCP packets. Among the
packets that nfqtrace receives from the nfqueue we identify all the
flows and keep track of them. We periodically alter a packet from the
stream and set it's TTL differently such that it may result in a ICMP
TTL-expired response from a distant router.

what is NFQueue?
----------------

main features

* receiving queued packets from the kernel nfnetlink_queue subsystem

* issuing verdicts and/or reinjecting altered packets to the kernel nfnetlink_queue subsystem


more info here

http://www.netfilter.org/projects/libnetfilter_queue/index.html



status
------
Alpha version is working and ready for non-production use.

software dependencies
---------------------
1. Linux kernel 2.6.14 or later
2. libnetfilter-queue_0.0.17 or later
3. https://github.com/david415/go-netfilter-queue

installation procedure
----------------------
for debian based systems this or something similar should work

1. sudo apt-get install libnetfilter-queue-dev libpcap-dev
2. go get github.com/david415/ParasiticTraceroute


note: you must have your golang build environment setup properly to build **go-netfilter-queue**


usage
-----

**you must set an iptables rule so that packets are sent to the nfqueue!**

perform reverse TCP traceroute on all connections to a local server like this::

   iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --sport 9000

perform forward TCP traceroute on all connections from a locatl client like this::

   iptables -A OUTPUT -j NFQUEUE --queue-num 0 -p tcp --dport 22

**note:** It only makes sense to use nfqTrace against packets that are outgoing (as opposed to incoming). It should also be be obvious... the NF Queue ID in your iptables rule must match the ID specified to nfqTrace!

currently this is what the usage looks like::

   $ ./nfqTrace  -h
   Usage of ./nfqTrace:
     -interface="wlan0": Interface to get packets from
     -log-file="nfqtrace.log": log file
     -maxttl=30: Maximum TTL that will be used in the traceroute
     -packetfreq=6: Number of packets that should traverse a flow before we mangle the TTL
     -queue-id=0: NFQueue ID number
     -queue-size=10000: Maximum capacity of the NFQueue
     -timeout=30: Number of seconds to await a ICMP-TTL-expired response
     -ttlrepeat=3: Number of times each TTL should be sent


future features
---------------
1. session close detection
2. end of trace detection
3. set and remove cleanly the iptables nfqueue rule
4. use setcap facility and drop privileges
5. add a timestamp to each result item
6. add packet round trip time to each result item
7. repeatedly perform the trace on connections that stay open; This feature addition implies contiuously appending to a trace result list for a given connction...
8. optionally do not man-in-the-middle stream packets but send out "duplicates" instead
9. add option to stream results to stdout instead of a file


=================================
nfqtraceClient and nfqtraceServer
=================================

abstract
--------
Bidirectional TCP traceroute using a cooperative client server protocol.


status
------
**Design phase.**


design notes
------------

* client and server tcp protocol using JSON to distringuish trace results from noise-data used to generate the trace...
* server streams results to client as soon as available ( clients determins it's own TCP source port and uses that to track the outgoing NFQueue flow


usage notes
-----------

These are represent a rought sketch... and to be clear there must be many more commandline options; all the options that nfqtrace has apply here.

* nfqclient <server ip>:<server port> -client-mangle-freq <int> -client-send-dups=<bool> -server-mangle-freq=<int> -server-send-dups=<bool>

* nfqserver -interface=<network interface> -port=<tcp port>


================
acknowledgements
================

* This development effort is a direct result from design discussions with Leif Ryge and Aaron Gibson, advisors/consultants for the Tor Project.

* Krishna Raman <kraman@gmail.com> has written most of the code the `go-netfilter-queue` library that I use. I recently added the packet injection capability to the library which can be found here: https://github.com/david415/go-netfilter-queue Merge to upstream pending 3rd party code review. Any takers?


=======
contact
=======

* Please do **use the GitHub issue-tracker** to report bugs.
* Code reviews welcome... please! It's difficult for me to find competent developers that can review my code.
* Pull requests welcome.
* Collaboration with software developers, network engineers and malware/botnet experts welcome.
* Feature requests welcome.


contact info
------------

* email dstainton415@gmail.com
* gpg key ID 0x836501BE9F27A723
* gpg fingerprint F473 51BD 87AB 7FCF 6F88  80C9 8365 01BE 9F27 A723

It may also be possible to contact me as ``dawuud`` in #tor-dev and #ooni on `OFTC <http://www.oftc.net/oftc/>`_
