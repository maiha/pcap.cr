SHELL=/bin/bash
CRYSTAL ?= crystal
LINK_FLAGS = --link-flags "-static"
SRCS = ${wildcard examples/*.cr}
PROGS = $(SRCS:examples/%.cr=%)

VERSION=
CURRENT_VERSION=$(shell git tag -l | sort -V | tail -1)
GUESSED_VERSION=$(shell git tag -l | sort -V | tail -1 | awk 'BEGIN { FS="." } { $$3++; } { printf "%d.%d.%d", $$1, $$2, $$3 }')

.SHELLFLAGS = -o pipefail -c

.PHONY : all clean bin ci spec
.PHONY : ${PROGS}

all: static

ci: check_version_mismatch clean static spec

static: bin ${PROGS}

bin:
	@mkdir -p bin

tcpsniffer: examples/tcpsniffer.cr
	$(CRYSTAL) build --release $^ -o bin/$@ ${LINK_FLAGS}

tcpbody: examples/tcpbody.cr
	$(CRYSTAL) build --release $^ -o bin/$@ ${LINK_FLAGS}

filtertest: examples/filtertest.cr
	$(CRYSTAL) build --release $^ -o bin/$@ ${LINK_FLAGS}

spec:
	$(CRYSTAL) spec -v

compile:
	@set -e; \
	for x in examples/*.cr ; do\
	  $(CRYSTAL) build "$$x" -o /dev/null ;\
	done

clean:
	@rm -rf bin tmp

.PHONY : check_version_mismatch
check_version_mismatch: shard.yml README.md
	diff -w -c <(grep version: README.md | head -1) <(grep ^version: shard.yml)

.PHONY : version
version:
	@if [ "$(VERSION)" = "" ]; then \
	  echo "ERROR: specify VERSION as bellow. (current: $(CURRENT_VERSION))";\
	  echo "  make version VERSION=$(GUESSED_VERSION)";\
	else \
	  sed -i -e 's/^version: .*/version: $(VERSION)/' shard.yml ;\
	  sed -i -e 's/^    version: [0-9]\+\.[0-9]\+\.[0-9]\+/    version: $(VERSION)/' README.md ;\
	  echo git commit -a -m "'$(COMMIT_MESSAGE)'" ;\
	  git commit -a -m 'version: $(VERSION)' ;\
	  git tag "v$(VERSION)" ;\
	fi

.PHONY : bump
bump:
	make version VERSION=$(GUESSED_VERSION) -s
