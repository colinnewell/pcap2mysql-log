VERSION  := $(shell git describe --tags 2>/dev/null || git rev-parse --short HEAD)
DC := docker-compose -f test/docker-compose.yml

all: pcap2mysql-log pcap2mysql-summaries

pcap2mysql-summaries: cmd/pcap2mysql-summaries/* go*
	go build -o pcap2mysql-summaries -ldflags "-X main.Version=$(VERSION)" cmd/pcap2mysql-summaries/*.go

pcap2mysql-log: cmd/pcap2mysql-log/*.go pkg/*/* pkg/*/*/* go.*
	go build -o pcap2mysql-log -ldflags "-X github.com/colinnewell/pcap-cli/cli.Version=$(VERSION)" cmd/pcap2mysql-log/*.go

test: pcap2mysql-log pcap2mysql-summaries go-test e2e-test

go-test: .force
	go test ./...

e2e-test: pcap2mysql-log
	./e2e-test.sh

# fake target (don't create a file or directory with this name)
# allows us to ensure a target always gets run, even if there is a folder or
# file with that name.
# This is different to doing make -B to ensure you do a rebuild.
# This is here because we have a test directory which makes the make test think
# it's 'built' already.
.force:

clean:
	rm pcap2mysql-log pcap2mysql-summaries

install: pcap2mysql-log pcap2mysql-summaries
	cp pcap2mysql-log pcap2mysql-summaries /usr/local/bin

lint:
	golangci-lint run
	./ensure-gofmt.sh

captures: go-captures perl-captures

go-captures:
	${DC} down
	${DC} build
	${DC} run --rm test || ${DC} logs
	${DC} down

perl-captures:
	${DC} down
	${DC} build
	${DC} run --rm test-perl || ${DC} logs
	${DC} down

fuzz:
	go get github.com/dvyukov/go-fuzz/go-fuzz \
			github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build
	go-fuzz -bin fuzz-fuzz.zip
