# usage: (run as root)
#   crystal examples/tcpdump.cr
#   crystal examples/tcpdump.cr -- -v
#   crystal examples/tcpdump.cr -- -p 6379
#   crystal examples/tcpdump.cr -- -f '(tcp port 80) or (tcp port 8080)' 
#   crystal examples/tcpdump.cr -- -i eth0 -p 80

require "../src/pcap"
require "option_parser"

filter  = "tcp port 80"
device  = "lo"
snaplen = 68
timeout = 1000
verbose = false

oparse = OptionParser.parse! do |parser|
  parser.banner = "Usage: #{$0} [options]"

  parser.on("-i lo", "--interface=lo", "\tNetworking interface") { |i|
    device = i
  }
  parser.on("-f tcp port 80", "--filter=tcp port 80", "\tPcap filter") { |f|
    filter = f
  }
  parser.on("-p 80", "--port=80", "\tPcap port") { |p|
    filter = "tcp port #{p}"
  }
  parser.on("-s 1500", "--snaplen=1500", "\tSnap length max 65535 (default: 68)") { |s|
    snaplen = s.to_i
  }
  parser.on("-v", "--verbose", "\tShow verbose output") {
    verbose = true
  }
  parser.on("-h", "--help", "Show this help") { |h|
    puts parser
    exit 0
  }
end
oparse.parse!

cap = Pcap::Capture.open_live(device, snaplen: snaplen, timeout_ms: timeout)
at_exit { cap.close }
cap.setfilter(filter)

handler =
  if verbose
    Pcap::Handler.new { |data, h, bytes|
      puts "-"*80
      p Pcap::Packet.new(data, h, bytes)
    }
  else
    Pcap::Handler.new { |data, h, bytes|
      puts Pcap::Packet.new(data, h, bytes)
    }
  end

cap.loop(handler)

