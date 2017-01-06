SHELL = /bin/bash
LINK_FLAGS = --link-flags "-static"
SRCS = ${wildcard examples/*.cr}
PROGS = $(SRCS:examples/%.cr=%)

.PHONY : all clean bin test spec
.PHONY : ${PROGS}

all: static

test: check_version_mismatch compile static version spec

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


.PHONY : check_version_mismatch
check_version_mismatch: shard.yml README.md
	diff -w -c <(grep version: README.md | head -1) <(grep ^version: shard.yml)
