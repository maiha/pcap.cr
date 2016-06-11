# pcap.cr

Crystal bindings for `libpcap`

## Status

- support only tcp

## TODO

- [x] `libpcap` api (0.1.0)
- [ ] Crystal closure support in `Pcap::Handler`
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

handler = Pcap::Handler.new { |data, h, bytes|
  pkt = Pcap::Packet.new(data, h, bytes)
  # p pkt.ether_header
  # p pkt.ip_header
  # p pkt.tcp_header
  if pkt.tcp_data?
    p pkt.tcp_data.to_s
  end
}

cap.loop(handler)

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

#### `tcpdump -X`

```shell
% crystal examples/tcpdump.cr
% crystal examples/tcpdump.cr -- -p 6379
% crystal examples/tcpdump.cr -- -f '(tcp port 80) or (tcp port 8080)' 
% crystal examples/tcpdump.cr -- -i eth0 -p 80
```

- send some packets like `curl localhost`

```
22:27:08.419116 IP 127.0.0.1.54054 > 127.0.0.1.80: Flags [S], seq 607415934, win 43690, length 4294967290
        0x0000:  0000 0000 0000 0000 0000 0000 0800 4500  ..............E.
        0x0010:  003c c199 4000 4006 7b20 7f00 0001 7f00  .<..@.@.{ ......
        0x0020:  0001 d326 0050 2434 6e7e 0000 0000 a002  ...&.P$4n~......
        0x0030:  aaaa fe30 0000 0204 ffd7 0402 080a 071f  ...0............
        0x0040:  afe7 0000                                ....
22:27:08.419173 IP 127.0.0.1.80 > 127.0.0.1.54054: Flags [SA], seq 2290657103, ack 607415935, win 43690, length 4294967290
        0x0000:  0000 0000 0000 0000 0000 0000 0800 4500  ..............E.
...
```

#### debug

- `-v` options make output verbose via `inspect`

```shell
% crystal examples/tcpdump.cr -- -v
```

- send some packets like `curl localhost`

```
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

## Contributing

1. Fork it ( https://github.com/maiha/pcap.cr/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [[maiha]](https://github.com/maiha) maiha - creator, maintainer
- [[puppetpies]](https://github.com/puppetpies) Brian Hood - `libpcap.cr`
