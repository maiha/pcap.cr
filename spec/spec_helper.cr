require "spec"
require "../src/pcap"

def fixture_path(name)
  "#{__DIR__}/fixtures/#{name}"
end

def fixtures(name)
  File.read("#{__DIR__}/fixtures/#{name}")
end

def load_packet(name) : Pcap::Packet
  path = fixture_path(name)
  size = File.size(path)
  slice = Slice(UInt8).new(size)
  File.open(path) do |f|
    f.read_fully(slice)
  end

  header = pointerof(slice).as(Pointer(LibPcap::PcapPkthdr))
  data = pointerof(slice).as(Pointer(LibPcap::UChar))
  packet = Pcap::Packet.new(header, data)
  return packet
end

def load_packet_from_file(name) : Pcap::Packet
  bytes = [] of UInt8
  File.each_line("#{__DIR__}/fixtures/packets/#{name}") do |line|
    # 0x0010:  003c 80f8 4000 4006 bbc1 7f00 0001 7f00  .<..@.@.........
    case line
    when /:\s{2,}(([0-9a-f]{4} ){1,7}([0-9a-f]{1,4}))\s{2,}/
      buf = $1 # "003c 80f8 4000 4006 bbc1 7f00 0001 7f00"
      buf.scan(/([0-9a-f])([0-9a-f])/) do
        u8 = ($1[0].to_i(16).to_u8 * 16) + ($2[0].to_i(16).to_u8)
        bytes << u8
      end
    end
  end

  header = bytes.to_unsafe.as(Pointer(LibPcap::PcapPkthdr))
  data = bytes.to_unsafe.as(Pointer(LibPcap::UChar))
  packet = Pcap::Packet.new(header, data)
  return packet
end
