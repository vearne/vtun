#!/bin/bash

#Linux amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/vtun-linux-amd64 ./main.go
#Linux arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ./bin/vtun-linux-arm64 ./main.go
#Mac amd64
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o ./bin/vtun-darwin-amd64 ./main.go
#Mac arm64
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o ./bin/vtun-darwin-arm64 ./main.go
#Openwrt mipsel_24kc
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o ./bin/vtun-mipsel-24kc ./main.go

echo "DONE!!!"
