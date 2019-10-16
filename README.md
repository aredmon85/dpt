# dpt
Data Plane Tester - Packet Generation Tool Written in C Raw Sockets

Written in raw sockets - requires root to run

It's recommended to run dpt using taskset to avoid irqbalance altering queue and cores during operation.

Examples:

Source address: 10.10.0.31
Destination address: 10.10.0.32
Protocol: UDP (17)
Destinatio port: 53
Frame size: 64B
Number of flows: 32
TOS: 6
Run duration: 30
TTL: 64
Packets Per Second: 10,000

sudo taskset -c 0 ./dpt 10.10.0.32 -s 10.10.0.31 -p 17 -P 53 -l 64 -f 32 -q 6 -d 30 -t 64 -r 10000

Source address: 10.10.0.36
Destination address: 10.10.0.35
Protocol: GRE (47, UDP encapsulated in GRE)
Destinatio port: 53
Frame size: 128B
Number of flows: 32
TOS: 6
Run duration: 30
TTL: 64
Packets Per Second: 20,000

sudo taskset -c 0 ./dpt 10.10.0.35 -s 10.10.0.36 -p 47 -P 53 -l 128 -f 32 -q 6 -d 30 -t 64 -r 20000
