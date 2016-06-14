require "./spec_helper"

describe Pcap::Capture do
  describe ".open_offline" do
    it "can reply packets" do
      datas = [] of String

      pcap = Pcap::Capture.open_offline(fixture_path("ipv4/redis-ping.cap"))
      pcap.loop do |pkt|
        datas << pkt.tcp_data.to_s if pkt.tcp_data?
      end

      datas.size.should eq(2)
      datas.shift.should eq("*1\r\n$4\r\nping\r\n")
      datas.shift.should eq("+PONG\r\n")
    end
  end
end
