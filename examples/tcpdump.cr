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
snaplen = 65535
timeout = 1000
hexdump = false
verbose = false

oparse = OptionParser.parse! do |parser|
  parser.banner = "Usage: #{$0} [options]"

  parser.on("-i lo", "Listen on interface") { |i| device = i }
  parser.on("-f 'tcp port 80'", "filter"  ) { |f| filter = f }
  parser.on("-p 80", "Pcap port"          ) { |p| filter = "tcp port #{p}" }
  parser.on("-s 65535", "Snapshot length" ) { |s| snaplen = s.to_i }
  parser.on("-x", "Show hexdump output"   ) { hexdump = true }
  parser.on("-v", "Show verbose output"   ) { verbose = true }
  parser.on("-h", "--help", "Show help"   ) { puts parser; exit 0 }
end
oparse.parse!

# TODO: DRY UP by closure support
handler =
  case [hexdump, verbose]
  when [false, false]
    Pcap::Handler.new { |data, h, bytes|
      pkt = Pcap::Packet.new(data, h, bytes)
      puts pkt.to_s
    }
  when [false, true]
    Pcap::Handler.new { |data, h, bytes|
      pkt =  Pcap::Packet.new(data, h, bytes)
      puts "-"*80
      p pkt
    }
  when [true, false]
    Pcap::Handler.new { |data, h, bytes|
      pkt = Pcap::Packet.new(data, h, bytes)
      puts pkt.to_s
      puts pkt.hexdump
    }
  when [true, true]
    Pcap::Handler.new { |data, h, bytes|
      pkt =  Pcap::Packet.new(data, h, bytes)
      puts "-"*80
      puts "-"*80
      p pkt
      puts pkt.hexdump
    }
  else
    raise "BUG: Logic for (hexdump, verbose)"
  end

begin
  cap = Pcap::Capture.open_live(device, snaplen: snaplen, timeout_ms: timeout)
  at_exit { cap.close }
  cap.setfilter(filter)
  cap.loop(handler)
rescue err
  STDERR.puts "#{$0}: #{err}"
end
