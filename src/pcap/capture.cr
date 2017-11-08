require "./packet"

module Pcap
  class Capture
    include Iterator(Packet)

    DEFAULT_SNAPLEN    =           1500
    DEFAULT_PROMISC    =              1
    DEFAULT_TIMEOUT_MS =           1000
    DEFAULT_NETMASK    = 0xFFFFFF00_u32 # 255.255.255.0
    DEFAULT_OPTIMIZE   =              1

    def self.open_live(device : String, snaplen : Int32 = DEFAULT_SNAPLEN, promisc : Int32 = DEFAULT_PROMISC, timeout_ms : Int32 = DEFAULT_TIMEOUT_MS)
      errbuf = uninitialized UInt8[LibPcap::PCAP_ERRBUF_SIZE]
      pcap_t = LibPcap.pcap_open_live(device, snaplen, promisc, timeout_ms, errbuf)
      if pcap_t.null?
        raise Error.new(String.new(errbuf.to_unsafe))
      end
      return new(pcap_t)
    end

    def self.open_dead(linktype : Int32 = DEFAULT_LINKTYPE, snaplen : Int32 = DEFAULT_SNAPLEN)
      pcap_t = LibPcap.pcap_open_dead(linktype, snaplen)
      if pcap_t.null?
        raise "failed to call `pcap_open_dead`"
      end
      return new(pcap_t)
    end

    def self.open_offline(file : String)
      errbuf = uninitialized UInt8[LibPcap::PCAP_ERRBUF_SIZE]
      pcap_t = LibPcap.pcap_open_offline(file, errbuf)
      if pcap_t.null?
        raise Error.new(String.new(errbuf.to_unsafe))
      end
      return new(pcap_t)
    end

    @callback : Packet -> Nil
    property! :callback

    def initialize(@pcap : LibPcap::PcapT)
      @callback = ->(p : Packet) {}
    end

    def setfilter(filter : String, optimize : Int32 = DEFAULT_OPTIMIZE, netmask : UInt32 = DEFAULT_NETMASK)
      # compile first
      bpfprogram = Pointer(LibPcap::BpfProgram).malloc(1_u64)
      safe { LibPcap.pcap_compile(@pcap, bpfprogram, filter, optimize, netmask) }
      LibPcap.pcap_setfilter(@pcap, bpfprogram)
    end

    def compile(filter, optimize = DEFAULT_OPTIMIZE, netmask = DEFAULT_NETMASK)
      bpfprogram = Pointer(LibPcap::BpfProgram).malloc(1_u64)
      safe { LibPcap.pcap_compile(@pcap, bpfprogram, filter, optimize, netmask) }
      return bpfprogram
    end

    def set_promisc(flag : Bool)
      if flag == true
        flagset = 1
      else
        flagset = 0
      end
      LibPcap.pcap_set_promisc(@pcap, flagset)
    end

    # calls `pcap_loop` that fetches all packets in the next buffer, and loop forever.
    def loop(count : Int32 = -1, &callback : Pcap::Packet ->)
      @@callback = callback                        # ref to the object in order to avoid GC
      boxed = Box.box(callback).as(Pointer(UInt8)) # serialize to `UChar*` via `Void*`

      handler = Pcap::Handler.new { |_boxed, headp, bytes|
        pkt = Pcap::Packet.new(headp, bytes)
        cb = Box(typeof(callback)).unbox(_boxed.as(Pointer(Void))) # deserialize callback
        cb.call(pkt)
      }
      LibPcap.pcap_loop(@pcap, count, handler, boxed)
    end

    # calls `pcap_next_ex` that reads the next packet and returns a success/failure indication.
    def next_ex : NextError | Packet
      ret = LibPcap.pcap_next_ex(@pcap, out headp, out bytes)
      NextError.from_value?(ret) || Pcap::Packet.new(headp, bytes)
    end

    # called via `iterator`
    def next
      while (pkt = next_ex) == NextError::TIMEOUT
      end

      case pkt
      when Packet          ; return pkt
      when NextError::EOF  ; return stop
      when NextError::ERROR; raise Pcap::Error.new("next_ex failed with code=#{pkt}")
      else
        raise Pcap::Error.new("BUG: unexpected packet status: #{pkt.class}")
      end
    end

    # reads the next packet, and
    # - trys again if read timeouted
    # - returns `Pcap::Packet` if exists
    # - returns `nil` if EOF reached (maybe read in offline mode)
    # - raises `Pcap::Error` on error
    def get? : Packet?
      each.first
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
