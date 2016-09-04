SHELL = /bin/bash
LINK_FLAGS = --link-flags "-static"
SRCS = ${wildcard examples/*.cr}
PROGS = $(SRCS:examples/%.cr=%)

.PHONY : all clean bin test spec
.PHONY : ${PROGS}

all: static

test: spec compile static version

static: bin ${PROGS}

bin:
	@mkdir -p bin

tcpsniffer: examples/tcpsniffer.cr
	crystal build --release $^ -o bin/$@ ${LINK_FLAGS}

tcpbody: examples/tcpbody.cr
	crystal build --release $^ -o bin/$@ ${LINK_FLAGS}

spec:
	crystal spec -v

compile:
	@for x in examples/*.cr ; do\
	  crystal build "$$x" -o /dev/null ;\
	done

clean:
	@rm -rf bin tmp

version: ${PROGS}
	./bin/$^ --version
