

=====================================
nfqtrace library and commandline tool
=====================================

abstract
--------
The nfqTrace program performs TCP traceroutes on outgoing streams
whether they be from a TCP client or server. The Linux Netfilter
Queue facility is used to man-in-the-middle TCP packets. Among the
packets that nfqtrace receives from the nfqueue we identify all the
flows and keep track of them. We periodically alter a packet from the
stream and set its TTL differently such that it may result in a ICMP
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

This API could be used to create new interesting TCP traceroute related applications. Here's the godoc generated API documentation:
http://godoc.org/github.com/david415/ParasiticTraceroute/trace

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
1. end of trace detection
2. set and remove cleanly the iptables nfqueue rule
3. use setcap facility and drop privileges
4. add packet round trip time to each result item
5. repeatedly perform the trace on connections that stay open; This feature addition implies contiuously appending to a trace result list for a given connction...



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
