# pcap.cr

Crystal high level bindings for `libpcap`.
- `crystal-libpcap(libpcap.cr)` is a low level bindings for `libpcap` created by [puppetpies].
- `pcap.cr` is a wrapper for it and provides rich interface for packets like `ruby-pcap`.

```crystal
require "pcap"

cap = Pcap::Capture.open_live("eth0")
cap.setfilter("tcp port 80")
cap.loop do |pkt|
  if pkt.tcp_data?
    p pkt.tcp_data.to_s
  end
end
```

```
"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.47.0\r\nAccept: */*\r\n\r\n"
"HTTP/1.1 200 OK\r\nServer: nginx/1.10.0 (Ubuntu)\r\nDate: Mon, 13 Jun 2016 ...
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

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  pcap:
    github: maiha/pcap.cr
```
And then

```shell
% crystal deps
```

## Usage

```crystal
require "pcap"

cap = Pcap::Capture.open_live("eth0")
cap.setfilter("tcp port 80")
cap.loop do |pkt|
  # p pkt.ether_header
  # p pkt.ip_header
  # p pkt.tcp_header
  if pkt.tcp_data?
    p pkt.tcp_data.to_s
  end
}
```

## Examples

- (run as root)

#### `tcpbody`

- Sniffer redis commands

```shell
% crystal examples/tcpbody.cr -- 6379
```

- run some redis command like `redis-cli get foo`

```
"*2\r\n$3\r\nget\r\n$3\r\nfoo\r\n"
"$-1\r\n"
```

#### `tcpsniffer`

```shell
% crystal examples/tcpsniffer.cr
% crystal examples/tcpsniffer.cr -- -p 6379
% crystal examples/tcpsniffer.cr -- -f '(tcp port 80) or (tcp port 8080)' 
% crystal examples/tcpsniffer.cr -- -i eth0 -p 10080
```

- send some packets like `curl localhost`

```
12:29:01.445261 IP 127.0.0.1.56016 > 127.0.0.1.80: Flags [S], seq 746220255, win 43690, length 0
12:29:01.445282 IP 127.0.0.1.80 > 127.0.0.1.56016: Flags [SA], seq 4032610561, ack 746220256, win 43690, length 0
```

##### more output

- `-x` prints hexdump of packets

```
% crystal examples/tcpsniffer.cr -- -x
12:30:12.305080 IP 127.0.0.1.56018 > 127.0.0.1.80: Flags [S], seq 4253528483, win 43690, length 0
        0x0000:  0000 0000 0000 0000 0000 0000 0800 4500  ..............E.
        0x0010:  003c 8c99 4000 4006 b020 7f00 0001 7f00  .<..@.@.. ......
        0x0020:  0001 dad2 0050 fd87 b1a3 0000 0000 a002  .....P..........
        0x0030:  aaaa fe30 0000 0204 ffd7 0402 080a 092a  ...0...........*
        0x0040:  3d3a 0000 0000 0103 0307                 =:........
```

- `-v` prints packet structures (calls `inspect` internally)

```
% crystal examples/tcpsniffer.cr -- -v
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

```
% crystal examples/tcpsniffer.cr -- -b -d
17:12:24.261729: "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.47.0\r\nAccept: */*\r\n\r\n"
17:12:24.262003: "HTTP/1.1 200 OK\r\nServer: nginx/1.10.0 (Ubuntu)\r\nDate: Mon, 13 Jun 2016 ...
```

## Contributing

1. Fork it ( https://github.com/maiha/pcap.cr/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [[maiha]](https://github.com/maiha) maiha - creator, maintainer
- [[puppetpies]](https://github.com/puppetpies) Brian Hood - `libpcap.cr`
