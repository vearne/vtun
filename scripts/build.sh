#!bin/bash
export GO111MODULE=on

#Linux
GOOS=linux GOARCH=amd64 go build -o ./bin/vtun-linux-amd64 ./main.go
#Linux arm
GOOS=linux GOARCH=arm64 go build -o ./bin/vtun-linux-arm64 ./main.go
#Mac OS
GOOS=darwin GOARCH=amd64 go build -o ./bin/vtun-darwin-amd64 ./main.go
#Windows
GOOS=windows GOARCH=amd64 go build -o ./bin/vtun-windows-amd64.exe ./main.go

echo "DONE!!!"
