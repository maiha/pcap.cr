module Pcap
  module EtherTypes
    NAMES = {
      0x0800 => "IPv4",
      0x0806 => "ARP",
      0x8035 => "RARP",
      0x809b => "AppleTalk",
      0x86dd => "IPv6",
    }
  end
end
