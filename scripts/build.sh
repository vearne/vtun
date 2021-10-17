#!bin/bash
export GO111MODULE=on

#Linux amd64
GOOS=linux GOARCH=amd64 go build -o ./bin/vtun-linux-amd64 ./main.go
#Linux arm64
GOOS=linux GOARCH=arm64 go build -o ./bin/vtun-linux-arm64 ./main.go
#Mac amd64
GOOS=darwin GOARCH=amd64 go build -o ./bin/vtun-darwin-amd64 ./main.go
#Openwrt mipsel_24kc
GOOS=linux GOARCH=mipsle GOMIPS=softfloat -o ./bin/vtun-mipsel_24kc ./main.go

echo "DONE!!!"
