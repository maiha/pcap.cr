# usage: (run as root)
#   crystal examples/tcpsniffer.cr
#   crystal examples/tcpsniffer.cr -- -v
#   crystal examples/tcpsniffer.cr -- -p 6379
#   crystal examples/tcpsniffer.cr -- -f '(tcp port 80) or (tcp port 8080)' 
#   crystal examples/tcpsniffer.cr -- -i eth0 -p 80

require "../src/pcap"
require "option_parser"

filter   = "tcp port 80"
device   = "lo"
snaplen  = 1500
timeout  = 1000
hexdump  = false
verbose  = false
dataonly = false
bodymode = false
version  = false
whitespace = false

opts = OptionParser.new do |parser|
  parser.banner = "#{$0} version 0.2.1\n\nUsage: #{$0} [options]"

  parser.on("-i lo", "Listen on interface") { |i| device = i }
  parser.on("-f 'tcp port 80'", "Pcap filter string. See pcap-filter(7)"  ) { |f| filter = f }
  parser.on("-p 80", "Capture port (overridden by -f)") { |p| filter = "tcp port #{p}" }
  parser.on("-s 1500", "Snapshot length"  ) { |s| snaplen = s.to_i }
  parser.on("-d", "Filter packets where tcp data exists") { dataonly = true }
  parser.on("-b", "Body printing mode"    ) { bodymode = true }
  parser.on("-x", "Show hexdump output"   ) { hexdump  = true }
  parser.on("-v", "Show verbose output"   ) { verbose  = true }
  parser.on("-w", "Ignore all packets that contain only white spaces") { whitespace = true }
  parser.on("--version", "Print the version and exit") { version = true }
  parser.on("-h", "--help", "Show help"   ) { puts parser; exit 0 }
end

begin
  opts.parse!

  if version
    puts "tcpsniffer #{Pcap::VERSION}"
    exit
  end
  
  cap = Pcap::Capture.open_live(device, snaplen: snaplen, timeout_ms: timeout)
  at_exit { cap.close }
  cap.setfilter(filter)

  cap.loop do |pkt|
    next if dataonly && !pkt.tcp_data?

    if bodymode
      next if whitespace && pkt.tcp_data.to_s =~ /\A\s*\Z/
      puts "%s: %s" % [pkt.packet_header, pkt.tcp_data.to_s.inspect]
    else
      puts pkt.to_s
      puts "-" * 80     if verbose
      puts pkt.inspect  if verbose
      puts pkt.hexdump  if hexdump
    end
  end
rescue err
  STDERR.puts "#{$0}: #{err}"
end
