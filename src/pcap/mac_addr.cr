module Pcap
  class MacAddr
    def initialize(@raw : LibPcap::EthMac)
    end

    def inspect(io : IO)
      io << @raw.map { |uint16| "%02x" % uint16 }.join(":")
    end
  end
end
