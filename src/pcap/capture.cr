module Pcap
  class Capture
    DEFAULT_SNAPLEN    = 68
    DEFAULT_PROMISC    = 1
    DEFAULT_TIMEOUT_MS = 1000

    def self.open_live(device : String, snaplen : Int32 = DEFAULT_SNAPLEN, promisc : Int32 = DEFAULT_PROMISC, timeout_ms : Int32 = DEFAULT_TIMEOUT_MS)
      errbuf = uninitialized UInt8[LibPcap::PCAP_ERRBUF_SIZE]
      pcap_t = LibPcap.pcap_open_live(device, snaplen, promisc, timeout_ms, errbuf)
      if pcap_t.null?
        raise Error.new(String.new(errbuf.to_unsafe))
      end
      netmask = 16776960_u32 # of 0xFFFF00
      return new(pcap_t, netmask)
    end

    @callback : Packet -> Nil
    property! :callback

    def initialize(@pcap : LibPcap::PcapT, @netmask : UInt32)
      @callback = ->(p : Packet) {}
    end

    def setfilter(filter : String, optimize : Int32 = 1)
      # compile first
      bpfprogram = Pointer(LibPcap::BpfProgram).new
      safe { LibPcap.pcap_compile(@pcap, bpfprogram, filter, optimize, @netmask) }
      LibPcap.pcap_setfilter(@pcap, bpfprogram)
    end

    #    def loop(callback, count : Int32 = -1, user : String = "")
    #      LibPcap.pcap_loop(@pcap, count, callback, user)
    #    end

    def loop(callback)
      count = -1
      user = nil
      LibPcap.pcap_loop(@pcap, count, callback, user)
    end

    def loop(count : Int32 = -1, user : String? = nil)
      #      cb = Box
      #      handler = LibPcap::PcapHandler.new { |data, h, bytes|
      #        @callback.call(Packet.new(data, h, bytes))
      #      }
      #      LibPcap.pcap_loop(@pcap, count, handler, user)
    end

    def close
      LibPcap.pcap_close(@pcap)
    end

    private def safe
      ret = yield
      unless ret == 0 # 0: success
        raise Error.new(errmsg)
      end
    end
    private def errmsg
      String.new(LibPcap.pcap_geterr(@pcap))
    end
  end
end
