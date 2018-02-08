require "./spec_helper"

describe Pcap::IpHeader do
  describe "#to_s" do
    it "returns a String" do
      pcap = Pcap::Capture.open_offline(fixture_path("ipv4/redis-ping.cap"))
      pcap.get?.try(&.ip_header.to_s).should eq("IPv4 127.0.0.1>127.0.0.1")
    end
  end
end
