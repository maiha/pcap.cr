require "./spec_helper"

# assumes that `./bin/tcpsniffer` exists by `make static`

private def run(option)
  prog = "./bin/tcpsniffer"
  file = "spec/fixtures/ipv4/redis-ping.cap"

  fail "program not found: '#{prog}'\nrun 'make static' first" unless File.exists?(prog)
  fail "packet file not found: #{file}" unless File.exists?(file)
  # embed "-u" option in order to be independent from local timezone setting
  `#{prog} -r #{file} -u #{option} 2>/dev/null`
end

describe "tcpsniffer" do
  describe "-p 6379" do
    it "prints all packets for the given port" do
      run("-p 6379").should eq <<-EOF
        13:36:51.327153 IP 127.0.0.1.56903 > 127.0.0.1.6379: Flags [S], seq 3742863884, win 43690, length 0
        13:36:51.327193 IP 127.0.0.1.6379 > 127.0.0.1.56903: Flags [SA], seq 3534198769, ack 3742863885, win 43690, length 0
        13:36:51.327246 IP 127.0.0.1.56903 > 127.0.0.1.6379: Flags [A], ack 3534198770, win 342, length 0
        13:36:51.327346 IP 127.0.0.1.56903 > 127.0.0.1.6379: Flags [PA], seq 3742863885, ack 3534198770, win 342, length 14
        13:36:51.327395 IP 127.0.0.1.6379 > 127.0.0.1.56903: Flags [A], ack 3742863899, win 342, length 0
        13:36:51.327584 IP 127.0.0.1.6379 > 127.0.0.1.56903: Flags [PA], seq 3534198770, ack 3742863899, win 342, length 7
        13:36:51.327763 IP 127.0.0.1.56903 > 127.0.0.1.6379: Flags [A], ack 3534198777, win 342, length 0
        13:36:51.328072 IP 127.0.0.1.56903 > 127.0.0.1.6379: Flags [FA], ack 3534198777, win 342, length 0
        13:36:51.328303 IP 127.0.0.1.6379 > 127.0.0.1.56903: Flags [FA], ack 3742863900, win 342, length 0
        13:36:51.328386 IP 127.0.0.1.56903 > 127.0.0.1.6379: Flags [A], ack 3534198778, win 342, length 0

        EOF
    end
  end

  describe "-p 6379 -d" do
    it "prints filtered packets where payload data exist" do
      run("-p 6379 -d").should eq <<-EOF
        13:36:51.327346 IP 127.0.0.1.56903 > 127.0.0.1.6379: Flags [PA], seq 3742863885, ack 3534198770, win 342, length 14
        13:36:51.327584 IP 127.0.0.1.6379 > 127.0.0.1.56903: Flags [PA], seq 3534198770, ack 3742863899, win 342, length 7

        EOF
    end
  end

  describe "-p 6379 -b" do
    it "prints all packets with payload data" do
      # note: backslashes are escaped
      run("-p 6379 -b").should eq <<-EOF
        13:36:51.327153: ""
        13:36:51.327193: ""
        13:36:51.327246: ""
        13:36:51.327346: "*1\\r\\n$4\\r\\nping\\r\\n"
        13:36:51.327395: ""
        13:36:51.327584: "+PONG\\r\\n"
        13:36:51.327763: ""
        13:36:51.328072: ""
        13:36:51.328303: ""
        13:36:51.328386: ""

        EOF
    end
  end

  describe "-p 6379 -b -d" do
    it "prints filtered packets with payload data where payload data exist" do
      # note: backslashes are escaped
      run("-p 6379 -b -d").should eq <<-EOF
        13:36:51.327346: "*1\\r\\n$4\\r\\nping\\r\\n"
        13:36:51.327584: "+PONG\\r\\n"

        EOF
    end
  end

  describe "-p 6379 -b -d -c" do
    it "prints with color" do
      # note: backslashes are escaped
      run("-p 6379 -b -d -c").should eq <<-EOF
        \e[32m13:36:51.327346: "*1\\r\\n$4\\r\\nping\\r\\n"\e[0m
        13:36:51.327584: "+PONG\\r\\n"

        EOF
    end
  end

  describe "-p 6379 -b -d -F" do
    it "prints filtered packets with payload data and tcp flags where payload data exist" do
      # note: backslashes are escaped
      run("-p 6379 -b -d -F").should eq <<-EOF
        13:36:51.327346:[PA] "*1\\r\\n$4\\r\\nping\\r\\n"
        13:36:51.327584:[PA] "+PONG\\r\\n"

        EOF
    end
  end
end
