module Pcap
  class IpHeader
    Bomap.nop ip_vhl, ip_tos, ip_ttl, ip_proto
    Bomap.n16 ip_len, ip_id, ip_frag, ip_sum
    Bomap.n32 ip_src, ip_dst

    def initialize(@raw : LibPcap::IpHeader)
    end

    def ip_v
      (ip_vhl & 0xf0) >> 4
    end

    def ip_hl
      ip_vhl & 0x0f
    end

    def src
      IpAddr.new(ip_src)
    end

    def dst
      IpAddr.new(ip_dst)
    end

    def to_s(io : IO)
      io << "IPv%s %s>%s" % [ip_v, src, dst]
    end

    def inspect(io : IO)
      io << "IpHeader\n"
      io << "  Version         : %s\n" % ip_v
      io << "  Header Length   : %d words (%d bytes)\n" % [ip_hl, ip_hl*4]
      io << "  Service Type    : %s\n" % ip_tos
      io << "  Total Length    : %s\n" % ip_len
      io << "  Identification  : %s\n" % ip_id
      io << "  Flags           : %s\n" % ip_frag
      io << "  TTL             : %s\n" % ip_ttl
      io << "  Protocol        : %s\n" % ip_proto
      io << "  Header Checksum : %s\n" % ip_sum
      io << "  Src IP Addr     : %s\n" % src
      io << "  Dst IP Addr     : %s\n" % dst
    end

    module Optimized
      def src_str
        IpAddr.inspect(ip_src)
      end

      def dst_str
        IpAddr.inspect(ip_dst)
      end
    end

    include Optimized
  end
end
