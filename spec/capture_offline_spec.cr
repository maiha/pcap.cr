require "./spec_helper"

describe Pcap::Capture do
  describe ".open_offline" do
    it "returns a Capture object" do
      pcap = Pcap::Capture.open_offline(fixture_path("ipv4/redis-ping.cap"))
      pcap.should be_a(Pcap::Capture)
    end
  end
end
