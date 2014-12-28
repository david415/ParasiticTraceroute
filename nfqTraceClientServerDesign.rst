
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

