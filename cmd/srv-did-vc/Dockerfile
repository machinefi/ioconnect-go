FROM --platform=linux/amd64 golang:1.22 AS builder

WORKDIR /go/src

COPY go.mod go.mod
COPY go.sum go.sum

RUN GO111MODULE=on go mod download

COPY . .

RUN cd ./cmd/srv-did-vc && make build


# runtime
FROM --platform=linux/amd64 scratch AS runtime

COPY --from=builder /go/src/cmd/srv-did-vc/srv-did-vc /go/bin/srv-did-vc
EXPOSE 9999

WORKDIR /go/bin
ENTRYPOINT ["/go/bin/srv-did-vc"]
