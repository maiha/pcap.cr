module Pcap
  enum NextError : Int32
    EOF     = -2 # EOF or pcap_breakloop
    ERROR   = -1 #
    TIMEOUT =  0 # should be continued
  end
end
