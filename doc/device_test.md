1. run docker compose

```shell
docker-compose -f docker-compose.debug.yaml up
```

2. retrieve server KA did and export it to env var

```shell
export SRV_KA_DID=...
```

3. exchange token

```shell
export TOKEN=`curl -X POST -d '{"clientID":"did:io:0x637e7a6d4ff1da58d17ede9785c21d7837bec429"}' http://127.0.0.1:9000/issue_vc | jq -r .token`
```

4. use token to commit task

```shell
curl -X POST -d 'cipher text' --header "Authorization: Bearer $TOKEN"  http://127.0.0.1:9000/message
```

> need replace `cipher text` to encrypted plain request body
> plain body is '{"projectID": 1, "projectVersion": "0.1", "data": "{\"private_input\":\"14\", \"public_input\":\"3,34\", \"receipt_type\":\"Snark\"}"}'
