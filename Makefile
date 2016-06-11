SHELL = /bin/bash
LINK_FLAGS = --link-flags "-static"
SRCS = ${wildcard examples/*.cr}
PROGS = $(SRCS:examples/%.cr=%)

.PHONY : all build clean bin
.PHONY : ${PROGS}

all: build

build: bin ${PROGS}

bin:
	@mkdir -p bin

tcpdump: examples/tcpdump.cr
	crystal build --release $^ -o bin/$@ ${LINK_FLAGS}

tcpbody: examples/tcpbody.cr
	crystal build --release $^ -o bin/$@ ${LINK_FLAGS}

spec:
	crystal spec -v

test-compile-bin:
	@for x in examples/*.cr ; do\
	  crystal build "$$x" -o /dev/null ;\
	done

clean:
	@rm -rf bin tmp
