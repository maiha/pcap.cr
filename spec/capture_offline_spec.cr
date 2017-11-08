require "./spec_helper"

private def open_pcap(file)
  Pcap::Capture.open_offline(fixture_path(file))
end

describe Pcap::Capture do
  context "(open_offline)" do
    describe "#loop" do
      it "can reply packets" do
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
  end
end
