FROM golang:1.22 AS builder

WORKDIR /go/src
COPY ./ ./

RUN cd ./cmd/srv-applet-mgr && make build

# runtime
FROM scratch AS runtime

COPY --from=builder /go/src/build/srv-applet-mgr/srv-applet-mgr /go/bin/srv-applet-mgr
COPY --from=builder /go/src/build/srv-applet-mgr/openapi.json /go/bin/openapi.json
EXPOSE 9999

WORKDIR /go/bin
ENTRYPOINT ["/go/bin/srv-applet-mgr"]
