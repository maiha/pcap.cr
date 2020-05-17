# pcap.cr [![Build Status](https://travis-ci.org/maiha/pcap.cr.svg?branch=master)](https://travis-ci.org/maiha/pcap.cr)

Crystal high level bindings for `libpcap`.
- `crystal-libpcap(libpcap.cr)` is a low level bindings for `libpcap` created by [puppetpies].
- `pcap.cr` is a wrapper for it and provides rich interface for packets like `ruby-pcap`.

- Crystal: 0.31.1 0.32.1 0.33.0 0.34.0
- x86_64 binary: https://github.com/maiha/pcap.cr/releases

## Usage : loop with handler

- `Pcap::Capture#loop` : `NoReturn`

is a easiest way to read all packets, and loop forever.
`tcpdump` uses this style to capture packets.

```crystal
require "pcap"

pcap = Pcap::Capture.open_live("eth0")
pcap.setfilter("tcp port 80")
pcap.loop do |pkt|
  if pkt.tcp_data?
    # p pkt.ether_header
    # p pkt.ip_header
    # p pkt.tcp_header
    p pkt.tcp_data.to_s
  end
end
```

```
"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.47.0\r\nAccept: */*\r\n\r\n"
"HTTP/1.1 200 OK\r\nServer: nginx/1.10.0 (Ubuntu)\r\nDate: Mon, 13 Jun 2016 ...
```

## Usage : reads a packet without blocking

- `Pcap::Capture#next_ex` : `Pcap::NextError` | `Pcap::Packet`

reads a next packet without blocking.

```crystal
pkt = pcap.next_ex
case pkt
when Pcap::Packet            ; # use pkt as you like
when Pcap::NextError::Timeout; # try again
when Pcap::NextError::Error  ; abort "libpcap error"
when Pcap::NextError::EOF    ; # found only in offline mode
end
```

- `Pcap::Capture#get?` : `Pcap::Packet?`

is a easiest way to read a packet. This api would block because `get?` = `next_ex` + timeout retry.

```crystal
if pkt = pcap.get?
  puts pkt
else
  abort "EOF reached"
end
```

```
22:36:51.327153 IP 127.0.0.1.56903 > 127.0.0.1.6379: Flags [S], seq 3742863884, win 43690, length 0
```

## Status

- support only tcp

## TODO

- [x] `libpcap` api (0.1.0)
- [x] Crystal closure support in `Pcap::Handler` (0.2.0)
- [x] Ether Header (0.1.0)
  - [x] parse
  - [x] inspect
- [x] Ip Header (0.1.0)
  - [x] parse
  - [x] inspect
- [x] Tcp Header (0.1.0)
  - [x] parse
  - [x] inspect
- [ ] Udp Header
  - [ ] parse
  - [ ] inspect
- [ ] Other Headers
  - [ ] parse
  - [ ] inspect
- [ ] Test
  - [x] `Pcap::Capture` offline

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  pcap:
    github: maiha/pcap.cr
    version: 0.6.1
```
And then

```console
$ shards update
```

## Example applications

#### `filtertest`

Test a string of `pcap-filter`.

```console
$ filtertest 'tcp'
$ filtertest 'tcp 80'
syntax error
$ filtertest 'tcp port 80'
$ filtertest -f filter.data # for large string
```

(As it works, this command will not display any output.)

#### `tcpsniffer`

- (run as root)

```console
$ crystal examples/tcpsniffer.cr

# (or binary)
$ tcpsniffier -p 6379
$ tcpsniffier -f '(tcp port 80) or (tcp port 8080)' 
$ tcpsniffier -i eth0 -p 10080
```

- send some packets to your specified port by `curl localhost` 

```
12:29:01.445261 IP 127.0.0.1.56016 > 127.0.0.1.80: Flags [S], seq 746220255, win 43690, length 0
12:29:01.445282 IP 127.0.0.1.80 > 127.0.0.1.56016: Flags [SA], seq 4032610561, ack 746220256, win 43690, length 0
```

##### further output

- `-x` prints hexdump of packets

```console
$ tcpsniffer -x
12:30:12.305080 IP 127.0.0.1.56018 > 127.0.0.1.80: Flags [S], seq 4253528483, win 43690, length 0
        0x0000:  0000 0000 0000 0000 0000 0000 0800 4500  ..............E.
        0x0010:  003c 8c99 4000 4006 b020 7f00 0001 7f00  .<..@.@.. ......
        0x0020:  0001 dad2 0050 fd87 b1a3 0000 0000 a002  .....P..........
        0x0030:  aaaa fe30 0000 0204 ffd7 0402 080a 092a  ...0...........*
        0x0040:  3d3a 0000 0000 0103 0307                 =:........
```

- `-v` prints packet structures (calls `inspect` internally)

```console
$ tcpsniffer -v
--------------------------------------------------------------------------------
Packet Header
  Time         : 2016-06-11 22:42:09 +0900 (1465652529.994580)
  Packet Size  : 68 (total: 74) bytes

Ethernet Header
  Destination eth addr  : 00:00:00:00:00:00
  Source ether addr     : 00:00:00:00:00:00
  Packet type ID        : IPv4 (2048)

IpHeader
  Version         : 4
  Header Length   : 5 words (20 bytes)
  Service Type    : 0
  Total Length    : 60
  Identification  : 4307
  Flags           : 16384
  TTL             : 64
  Protocol        : 6
  Header Checksum : 11239
  Src IP Addr     : 127.0.0.1
  Dst IP Addr     : 127.0.0.1
...
```

- `-d` prints only packets where tcp data exist
- `-b` prints body oriented format (body mode)
- `-x` ignore all packets that contain only white spaces

```console
$ tcpsniffer -b -d
17:12:24.261729: "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.47.0\r\nAccept: */*\r\n\r\n"
17:12:24.262003: "HTTP/1.1 200 OK\r\nServer: nginx/1.10.0 (Ubuntu)\r\nDate: Mon, 13 Jun 2016 ...
```

- `-W DIR` writes each tcp data by file in the DIR

```console
$ tcpsniffer -p 6379 -d -W pcap
16:37:03.683540 IP 127.0.0.1.52182 > 127.0.0.1.6379: Flags [PA], seq 3176296709, ack 3372892385, win 342, length 14
16:37:03.683611 IP 127.0.0.1.6379 > 127.0.0.1.52182: Flags [PA], seq 3372892385, ack 3176296723, win 342, length 7

$ redis-cli ping
PONG

$ ls -l pcap
-rw-r--r-- 1 root root 14 Mar  6 16:37 1.pcap
-rw-r--r-- 1 root root  7 Mar  6 16:37 2.pcap

$ hd pcap/1.pcap
00000000  2a 31 0d 0a 24 34 0d 0a  50 49 4e 47 0d 0a        |*1..$4..PING..|
0000000e

$ hd pcap/2.pcap
00000000  2b 50 4f 4e 47 0d 0a                              |+PONG..|
00000007
```

##### replay

- `-r file` reads from pcap file (same as `tcpdump -r`)

```console
# record packets by root with tcpdump
$ tcpdump -i lo -s 0 -w /tmp/redis.dump 'port 6379'

# in other shell
$ redis-cli ping

# stop tcpdump by `Ctl-c`

# reply by tcpsniffer
$ tcpsniffer -r /tmp/redis.dump -p 6379 -b -d
reading from file: /tmp/redis.dump
11:47:14.001208: "*1\r\n$4\r\nping\r\n"
11:47:14.001569: "+PONG\r\n"
```

## Contributing

1. Fork it ( https://github.com/maiha/pcap.cr/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [maiha](https://github.com/maiha) maiha - creator, maintainer
- [puppetpies](https://github.com/puppetpies) Brian Hood - `libpcap.cr`
