FROM golang:buster AS build

RUN apt-get update && apt-get install -y libpcap-dev jq

COPY go.mod go.sum /src/pcap2mysql-log/
COPY cmd /src/pcap2mysql-log/cmd/
COPY internal /src/pcap2mysql-log/internal/
COPY pkg /src/pcap2mysql-log/pkg/
COPY test/captures /src/pcap2mysql-log/test/captures

WORKDIR /src/pcap2mysql-log

RUN go build -o pcap2mysql-log cmd/pcap2mysql-log/*

FROM build AS test

RUN go test ./...

FROM build AS lint

RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.37.1 \
    && go get -u golang.org/x/lint/golint
COPY .golangci.yml /.golangci.yml
RUN /go/bin/golangci-lint run

FROM debian:buster-slim AS binary

RUN apt-get update && apt-get install -y libpcap-dev
COPY --from=build /src/pcap2mysql-log/pcap2mysql-log /pcap2mysql-log

ENTRYPOINT ["/pcap2mysql-log"]
