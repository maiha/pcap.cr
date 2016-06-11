# usage: (run as root)
#   crystal examples/tcpbody.cr
#   crystal examples/tcpbody.cr -- 10080
#   crystal examples/tcpbody.cr -- 6379

require "../src/pcap"

port = ARGV.shift{ 80 }.to_i

cap = Pcap::Capture.open_live("lo", snaplen: 1500)
at_exit { cap.close }
cap.setfilter("tcp port #{port}")

handler =
  Pcap::Handler.new { |data, h, bytes|
    pkt = Pcap::Packet.new(data, h, bytes)
    if pkt.tcp_data?
      p pkt.tcp_data.to_s
    end
  }

cap.loop(handler)
