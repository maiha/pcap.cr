module Pcap
  class TcpData
    def initialize(@ptr : Pointer(UInt8), @len : UInt32)
    end

    def bytes
      if @len <= 0
        return Slice(UInt8).new(0)
      else
        return @ptr.to_slice(@len)
      end
    end

    def to_s(io : IO)
      ary = bytes.map{|v| to_printable(v)}
      io << String.new(Slice.new(ary.to_unsafe, ary.size))
    end

    private def to_printable(v)
      case v
      when 0x0a, 0x0d; v
      when 31..127 ; v
      else
        '.'.ord.to_u8
      end
    end
  end
end
