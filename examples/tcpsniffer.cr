# usage: (run as root)
#   crystal examples/tcpsniffer.cr
#   crystal examples/tcpsniffer.cr -- -v
#   crystal examples/tcpsniffer.cr -- -p 6379
#   crystal examples/tcpsniffer.cr -- -f '(tcp port 80) or (tcp port 8080)'
#   crystal examples/tcpsniffer.cr -- -i eth0 -p 80

require "colorize"
require "../src/pcap"
require "option_parser"

filter = "tcp port 80"
device = "lo"
snaplen = 1500
timeout = 1000
hexdump = false
verbose = false
dataonly = false
bodymode = false
filemode = false
tcpflags = false
writedir = nil
dstcount = 0
colorize = false
version = false
readfile = ""
whitespace = false

opts = OptionParser.new do |parser|
  parser.banner = "#{PROGRAM_NAME} version #{Pcap::VERSION}\n\nUsage: #{PROGRAM_NAME} [options]"

  parser.on("-i lo", "Listen on interface") { |i| device = i }
  parser.on("-f 'tcp port 80'", "Pcap filter string. See pcap-filter(7)") { |f| filter = f }
  parser.on("-p 80", "Capture port (overridden by -f)") { |p| filter = "tcp port #{p}" }
  parser.on("-s 1500", "Snapshot length") { |s| snaplen = s.to_i }
  parser.on("-r file", "Read packets from file") { |d| readfile = d; filemode = true }
  parser.on("-d", "Filter packets where tcp data exists") { dataonly = true }
  parser.on("-b", "Body printing mode") { bodymode = true }
  parser.on("-c", "Show colorized output") { colorize = true }
  parser.on("-F", "Show tcp flags in body") { tcpflags = true }
  parser.on("-u", "Show header in UTC") { Pcap.use_local_time = false }
  parser.on("-x", "Show hexdump output") { hexdump = true }
  parser.on("-v", "Show verbose output") { verbose = true }
  parser.on("-w", "Ignore all packets that contain only white spaces") { whitespace = true }
  parser.on("-W DIR", "Write each tcp data by file in the DIR") { |v| writedir = v }
  parser.on("--version", "Print the version and exit") { version = true }
  parser.on("-h", "--help", "Show help") { puts parser; exit 0 }
end

private macro is_dst_packet(pkt)
  server_ports.includes?({{pkt}}.tcp_header.dst)
end

private macro with_color(color, message)
  (colorize ? {{message}}.colorize({{color}}) : {{message}})
end

private macro puts_with_color(buffer)
  if colorize && server_ports.any?
    if server_ports.includes?(pkt.tcp_header.dst)
      puts ({{buffer}}).colorize(:green)
    else
      puts {{buffer}}
    end
  else
    puts {{buffer}}
  end
end

private def extract_ports(filter) : Set(Int32)
  # TODO: find strictly
  Set(Int32).new.tap { |set| filter.scan(/(\d+)/) { set << $1.to_i } }
end

begin
  opts.parse

  server_ports = extract_ports(filter)

  if version
    puts "tcpsniffer #{Pcap::VERSION}"
    exit
  end

  if dir = writedir
    File.directory?(dir) || Dir.mkdir(dir)
  end

  if filemode
    STDERR.puts "reading from file: #{readfile}".colorize(:blue)
    cap = Pcap::Capture.open_offline(readfile)
  else
    cap = Pcap::Capture.open_live(device, snaplen: snaplen, timeout_ms: timeout)
  end

  at_exit { cap.close }
  cap.setfilter(filter)

  prev_dst = nil
  cap.loop do |pkt|
    next if dataonly && !pkt.tcp_data?

    if writedir
      is_dst = is_dst_packet(pkt)
      d_or_s = is_dst ? "d" : "s"

      # TODO: Support multiple responses to enable following codes.
#      dstcount += 1 if is_dst
#      path = "%s/%d%s.pcap" % [writedir, dstcount, d_or_s]

      dstcount += 1
      path = "%s/%d%s.pcap" % [writedir, dstcount, d_or_s]
      File.write(path, pkt.tcp_data.bytes)
    end

    if bodymode
      next if whitespace && pkt.tcp_data.to_s =~ /\A\s*\Z/
      flags = tcpflags ? "[#{pkt.tcp_header.tcp_flags}]" : ""
      puts_with_color "%s:%s %s" % [pkt.packet_header, flags, pkt.tcp_data.to_s.inspect]
    else
      puts_with_color pkt.to_s
      puts "-" * 80 if verbose
      puts pkt.inspect if verbose
      puts pkt.hexdump if hexdump
    end
  end
rescue err
  STDERR.puts "#{PROGRAM_NAME}: #{err}"
end
