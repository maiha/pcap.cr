module Pcap
  class IpAddr
    def self.inspect(v : UInt32)
      # [THIS IS SLOW]
      # "%s.%s.%s.%s" % [
      #   (v & 0xff000000) >> 24,
      #   (v & 0x00ff0000) >> 16,
      #   (v & 0x0000ff00) >> 8,
      #   (v & 0x000000ff),
      # ]

      "#{(v & 0xff000000) >> 24}.#{(v & 0x00ff0000) >> 16}.#{(v & 0x0000ff00) >> 8}.#{v & 0x000000ff}"
    end

    property value

    def initialize(@value : UInt32)
    end

    def to_s(io : IO)
      inspect(io)
    end

    def inspect(io : IO)
      io << self.class.inspect(@value)
    end
  end
end
