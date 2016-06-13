# usage: (run as root)
#   crystal examples/tcpsniffer.cr
#   crystal examples/tcpsniffer.cr -- -v
#   crystal examples/tcpsniffer.cr -- -p 6379
#   crystal examples/tcpsniffer.cr -- -f '(tcp port 80) or (tcp port 8080)' 
#   crystal examples/tcpsniffer.cr -- -i eth0 -p 80

require "../src/pcap"
require "option_parser"

filter  = "tcp port 80"
device  = "lo"
snaplen = 1500
timeout = 1000
hexdump = false
verbose = false

oparse = OptionParser.parse! do |parser|
  parser.banner = "Usage: #{$0} [options]"

  parser.on("-i lo", "Listen on interface") { |i| device = i }
  parser.on("-f 'tcp port 80'", "Pcap filter string. See pcap-filter(7)"  ) { |f| filter = f }
  parser.on("-p 80", "Capture port (overridden by -f)") { |p| filter = "tcp port #{p}" }
  parser.on("-s 1500", "Snapshot length"  ) { |s| snaplen = s.to_i }
  parser.on("-x", "Show hexdump output"   ) { hexdump = true }
  parser.on("-v", "Show verbose output"   ) { verbose = true }
  parser.on("-h", "--help", "Show help"   ) { puts parser; exit 0 }
end
oparse.parse!

begin
  cap = Pcap::Capture.open_live(device, snaplen: snaplen, timeout_ms: timeout)
  at_exit { cap.close }
  cap.setfilter(filter)

  cap.loop do |pkt|
    puts pkt.to_s
    puts "-" * 80    if verbose
    puts pkt.inspect if verbose
    puts pkt.hexdump if hexdump
  end
rescue err
  STDERR.puts "#{$0}: #{err}"
end
