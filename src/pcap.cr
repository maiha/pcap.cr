require "./libpcap"
require "./bomap"

module Pcap
  class Error < Exception
  end

  Handler = LibPcap::PcapHandler 
end

require "./pcap/**"
