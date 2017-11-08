require "./spec_helper"

private def open_pcap(file)
  Pcap::Capture.open_offline(fixture_path(file))
end

describe Pcap do
  describe "#loop" do
    it "reads all packets from pcap file" do
      datas = [] of String

      pcap = open_pcap("ipv4/redis-ping.cap")
      pcap.loop do |pkt|
        datas << pkt.tcp_data.to_s if pkt.tcp_data?
      end

      datas.size.should eq(2)
      datas.shift.should eq("*1\r\n$4\r\nping\r\n")
      datas.shift.should eq("+PONG\r\n")
    end
  end

  describe "#next_ex" do
    it "reads a current packet" do
      pcap = open_pcap("ipv4/redis-ping.cap")
      pkt = pcap.next_ex
      pkt.should be_a(Pcap::Packet)
    end
  end

  describe "#each" do
    it "provides iterator" do
      pcap = open_pcap("ipv4/redis-ping.cap")
      datas = pcap.each.select(&.tcp_data?).map(&.tcp_data.to_s).to_a

      datas.size.should eq(2)
      datas.shift.should eq("*1\r\n$4\r\nping\r\n")
      datas.shift.should eq("+PONG\r\n")
    end
  end

  describe "#get?" do
    it "returns a next packet without blocking" do
      pcap = open_pcap("ipv4/redis-ping.cap")
      pcap.get?.should be_a(Pcap::Packet)
    end
  end
end
