require "./libpcap"
require "./bomap"
require "./macros"
require "shard"

module Pcap
  VERSION = Shard.git_description.split(/\s+/, 2).last

  class Error < Exception
  end

  Handler = LibPcap::PcapHandler

  @@use_local_time : Bool = true

  def self.use_local_time
    @@use_local_time
  end

  def self.use_local_time=(v)
    @@use_local_time = v
  end
end

require "./pcap/**"
