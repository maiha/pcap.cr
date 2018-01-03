# [GOAL]
# - check the given pcap-filter string is valid or not by `pcap_compile`

require "../src/pcap"

def test(filter, optimize = 1, netmask = 0xFFFFFF00_u32, snaplen = 1000, linktype = 1)
  pcap = Pcap::Capture.open_dead(linktype, snaplen)
  pcap.compile(filter, optimize, netmask)
rescue err : Pcap::Error
  puts err
end

filter = ARGV.shift { abort "Usage: #{PROGRAM_NAME} filter-string" }
if filter == "-f"
  path = ARGV.shift { abort "Usage: #{PROGRAM_NAME} -f file" }
  filter = File.read(path)
end

test filter
