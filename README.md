# ioconnect-go

* wrap c library [ioConnect](https://github.com/machinefi/ioConnect)
* command line tool `didctl` for DID util 
* did verifiable credential token service `srv-did-vc`

[srv-did-vc docker registry](https://github.com/machinefi/ioconnect-go/pkgs/container/ioconnect-go)

## run container

```shell
docker run --name srv-did-vc -d ghcr.io/machinefi/ioconnect-go:main
```

## exchange vc token by client DID

```shell
curl -X POST -d '{"clientID":"did:io:0x637e7a6d4ff1da58d17ede9785c21d7837bec429"}' http://127.0.0.1:9999/issue
```

## verify vc token and retrieve client DID

```shell
$ curl -X POST -d '{"token":"..."}' http://127.0.0.1:9999/verify
```

