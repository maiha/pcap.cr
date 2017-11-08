module Pcap
  class EtherHeader
    Bomap.n16 ether_type

    def initialize(@raw : LibPcap::EtherHeader)
    end

    def dst
      MacAddr.new(@raw.ether_dhost)
    end

    def src
      MacAddr.new(@raw.ether_shost)
    end

    def inspect(io : IO)
      io << "Ethernet Header\n"
      io << "  Destination eth addr  : %s\n" % dst.inspect
      io << "  Source ether addr     : %s\n" % src.inspect
      io << "  Packet type ID        : %s (%s)\n" % [resolve_proto(ether_type), ether_type]
    end

    private def resolve_proto(v)
      EtherTypes::NAMES[v]? || "Unknown"
    end
  end
end
