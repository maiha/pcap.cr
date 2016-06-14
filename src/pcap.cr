require "./libpcap"
require "./bomap"
require "./macros"

module Pcap
  class Error < Exception
  end

  Handler = LibPcap::PcapHandler 
end

require "./pcap/**"
