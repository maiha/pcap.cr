require "./libpcap"
require "./bomap"
require "./macros"

module Pcap
  VERSION = "0.2.5"
  
  class Error < Exception
  end

  Handler = LibPcap::PcapHandler 

  @@use_local_time : Bool = true
  def self.use_local_time    ; @@use_local_time    ; end
  def self.use_local_time=(v); @@use_local_time = v; end
end

require "./pcap/**"
