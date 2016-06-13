require "c/arpa/inet"

module Pcap
  class Packet
    property packet_header : Pcap::PacketHeader
    delegate caplen, len, @packet_header
    
    def initialize(headp : LibPcap::PcapPkthdr*, @data : LibPcap::UChar*)
      # headp : a pointer to the packet header structure
      # @data : a pointer to the raw packet bytes

      @packet_header = PacketHeader.new(headp.value)
    end

    def capture_slice
      @data.to_slice(caplen)
    end

    def data_slice
      offset = sizeof(LibPcap::EtherHeader)
      len = caplen - offset
      if len < 0
        raise Pcap::Error.new("invalid packet size: expected > 0, but got #{len}")
      end
      (@data + offset).to_slice(len)
    end

    def ether_header
      EtherHeader.new((@data.as(Pointer(LibPcap::EtherHeader))).value)
    end

    def ip_header
      ptr = @data + sizeof(LibPcap::EtherHeader)
      IpHeader.new((ptr.as(Pointer(LibPcap::IpHeader))).value)
    end

    def size_ip
      ip_header.ip_hl * 4
    end

    def size_tcp
      tcp_header.length
    end

    def tcp_header
      ptr = @data + sizeof(LibPcap::EtherHeader) + size_ip
      TcpHeader.new((ptr.as(Pointer(LibPcap::TcpHeader))).value, packet_header)
    end

    def tcp_data?
      tcp_header.tcp_data_offset < caplen
    end
    
    def tcp_data
      elen = sizeof(LibPcap::EtherHeader)
      ilen = sizeof(LibPcap::IpHeader)
      tlen = tcp_header.length
      offset = elen + ilen + tlen
      ptr = @data + offset
      len = caplen - offset

#      if len <= 0
#        raise Pcap::Error.new("invalid packet size: #{caplen}(caplen) < #{offset}(offset) = ether(#{elen}) + ip(#{ilen}) + tcp(#{tlen})")
#      end

      Pcap::TcpData.new(ptr, len)
    end

    def to_s(io : IO)
      # [goal]
      # 14:17:50.516090 IP 127.0.0.1.55768 > 127.0.0.1.80: Flags [S], seq 3879550979, win 43690, options [mss 65495,sackOK,TS val 68977683 ecr 0,nop,wscale 7], length 0

      # [14:17:50.516090]
      packet_header.to_s(io)
      io << " "
      tcp_header.to_s(io, ip_header)
    end

    # similar to "tcpdump -XX"
    def hexdump(io : IO)
      io << embed_memory_address(capture_slice.hexdump, " "*8)
    end

    def hexdump
      String.build {|io| hexdump(io) }
    end
    
    def inspect(io : IO)
      io << packet_header.inspect
      io << "\n"
      io << ether_header.inspect
      io << "\n"
      io << ip_header.inspect
      io << "\n"
      io << tcp_header.inspect
      if tcp_data?
        io << "\n"
        io << "TcpData\n"
        io << "  (%s bytes)\n" % tcp_header.tcp_data_size
        io << embed_memory_address(tcp_data.bytes.hexdump, " "*2)
      end
    end
    
    private def embed_memory_address(buf : String, prefix : String = "")
      i = 0
      buf.gsub(/^/m){ ("%s0x%03x0:  " % [prefix, i]).tap{i += 1} }
    end
  end
end
