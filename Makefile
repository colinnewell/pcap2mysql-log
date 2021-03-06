VERSION  := $(shell git describe --tags 2>/dev/null || git rev-parse --short HEAD)
DC := docker-compose -f test/docker-compose.yml

all: pcap2mysql-log

pcap2mysql-log: cmd/pcap2mysql-log/*.go internal/*/* pkg/*/* pkg/*/*/*
	go build -o pcap2mysql-log -ldflags "-X main.Version=$(VERSION)" cmd/pcap2mysql-log/*.go

test: go-test e2e-test

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
	rm pcap2mysql-log

install: pcap2mysql-log
	cp pcap2mysql-log /usr/local/bin

lint:
	golangci-lint run
	gofmt -l -s .

captures:
	${DC} down
	${DC} build
	${DC} run --rm test || ${DC} logs
	${DC} down

fuzz:
	go get github.com/dvyukov/go-fuzz/go-fuzz \
			github.com/dvyukov/go-fuzz/go-fuzz-build
	go-fuzz-build
	go-fuzz -bin fuzz-fuzz.zip
