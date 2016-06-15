module Pcap
  class TcpHeader
    Bomap.n16 tcp_src, tcp_dst, tcp_offx2, tcp_win, tcp_sum, tcp_urg
    Bomap.n32 tcp_seq, tcp_ack

    delegate caplen, to: @packet_header
    
    def initialize(@raw : LibPcap::TcpHeader, @packet_header : PacketHeader)
    end

    ######################################################################
    ### accessor

    def src
      tcp_src
    end
    
    def dst
      tcp_dst
    end
    
    ######################################################################
    ### native data
    
    def tcp_doff
      # "101001..." => "1010".to_i(2) => 10
      tcp_offx2.to_s(2)[0..3].to_i(2)
    end

    def tcp_data_offset
      elen = sizeof(LibPcap::EtherHeader)
      ilen = sizeof(LibPcap::IpHeader)
      tlen = length
      elen + ilen + tlen
    end

    def tcp_data_size
      caplen - tcp_data_offset
    end

    def length
      tcp_doff * 4
    end
    
    # tcp_flags
    {% for key in %w(FIN SYN RST PUSH ACK URG ECE CWR) %}
      def tcp_{{key.downcase.id}}?
        tcp_offx2 & LibPcap::TH_{{key.id}} > 0
      end

      def tcp_{{key.downcase.id}}(io : IO)
        if tcp_{{key.downcase.id}}?
          io << {{key[0..0]}}
        end
      end
    {% end %}

    def tcp_flags(io : IO)
      {% for key in %w(FIN SYN RST PUSH ACK URG ECE CWR) %}
        tcp_{{key.downcase.id}}(io)
      {% end %}
    end

    def tcp_flags
      String.build {|io| tcp_flags(io)}
    end
    
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    
    def to_s(io : IO, ip_header : IpHeader)
      # "IP 127.0.0.1.55768 > 127.0.0.1.80: Flags [S], seq 3879550979, win 43690, options [mss 65495,sackOK,TS val 68977683 ecr 0,nop,wscale 7], length 0"

      io << "IP %s.%s > %s.%s: " % [ip_header.src, tcp_src, ip_header.dst, tcp_dst]

      # "Flags [S], "
      io << "Flags ["
      tcp_flags(io)
      io << "], "

      # "seq 3879550979, "
      if tcp_syn? || tcp_push?
        io << "seq %s, " % tcp_seq
      end

      # "ack 1190235814, "
      if tcp_ack?
        io << "ack %s, " % tcp_ack
      end
      
      # "win 43690, "
      io << "win %s, " % tcp_win

      # "options [mss 65495,sackOK,TS val 68977683 ecr 0,nop,wscale 7], "
      # TODO
      
      # "length 0"
      io << "length %d" % tcp_data_size
    end

    def inspect(io : IO)
      io << "TcpHeader\n"
      io << "  Src Port            : %s\n" % tcp_src
      io << "  Dst Port            : %s\n" % tcp_dst
      io << "  Sequence Number     : %s\n" % tcp_seq
      io << "  Acknowledge Number  : %s\n" % tcp_ack
      io << "  (tcp_offx2)         : %s(%s)\n" % [tcp_offx2, tcp_offx2.to_s(2)]
      io << "    Data Offset       : %d words (%d bytes)\n" % [tcp_doff, length]
      io << "    Flags             : [%s]\n" % tcp_flags
      io << "      CWR               : %s\n" % tcp_cwr?
      io << "      ECE               : %s\n" % tcp_ece?
      io << "      URG               : %s\n" % tcp_urg?
      io << "      ACK               : %s\n" % tcp_ack?
      io << "      PUSH              : %s\n" % tcp_push?
      io << "      RST               : %s\n" % tcp_rst?
      io << "      SYN               : %s\n" % tcp_syn?
      io << "      FIN               : %s\n" % tcp_fin?
      io << "  Window Size         : %s\n" % tcp_win
      io << "  Checksum            : %s\n" % tcp_sum
      io << "  Urgent Pointer      : %s\n" % tcp_urg
    end
  end
end
