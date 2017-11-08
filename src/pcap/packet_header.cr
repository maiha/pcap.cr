module Pcap
  class PacketHeader
    # [pcap-int.h]
    # struct pcap_sf_pkthdr {
    #   struct pcap_timeval ts;     /* time stamp */
    #   bpf_u_int32 caplen;         /* length of portion present */
    #   bpf_u_int32 len;            /* length this packet (off wire) */
    # };

    # Bomap.n16 caplen, len
    Bomap.nop caplen, len
    delegate tv_sec, tv_usec, to: @raw.ts

    def initialize(@raw : LibPcap::PcapPkthdr)
    end

    def tv_msec
      tv_sec * 1000 + tv_usec / 1000
    end

    def time
      t = Time.epoch_ms(tv_msec)
      t = t.to_local if Pcap.use_local_time
      t
    end

    def captured_bytes
      caplen
    end

    def total_bytes
      len
    end

    def to_s(io : IO)
      # "14:17:50.516090"
      io << time.to_s("%H:%M:%S.")
      io << "%06d" % tv_usec
    end

    def inspect(io : IO)
      io << "Packet Header\n"
      io << "  Time         : %s (%s.%06d)\n" % [time.inspect, tv_sec, tv_usec]

      if captured_bytes == total_bytes
        io << "  Packet Size  : %d bytes\n" % captured_bytes
      else
        io << "  Packet Size  : %d (total: %d) bytes\n" % [captured_bytes, total_bytes]
      end
    end
  end
end
