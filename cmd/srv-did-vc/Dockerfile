FROM golang:1.22 AS builder

WORKDIR /go/src
COPY ./ ./

RUN cd ./cmd/srv-did-vc && make build

# runtime
FROM scratch AS runtime

COPY --from=builder /go/src/cmd/srv-did-vc/srv-did-vc /go/bin/srv-did-vc
EXPOSE 9999

WORKDIR /go/bin
ENTRYPOINT ["/go/bin/srv-did-vc"]
