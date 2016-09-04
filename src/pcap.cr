require "./libpcap"
require "./bomap"
require "./macros"

module Pcap
  VERSION = "0.2.1"
  
  class Error < Exception
  end

  Handler = LibPcap::PcapHandler 
end

require "./pcap/**"
