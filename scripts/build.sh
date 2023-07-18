#!/bin/bash
RELEASE_BIN_DIR='./bin/'
function create_dir() {
    if [ ! -d $1 ];then
        mkdir $1
    fi
}

function go_build() {
    suffix=''
    if [[ "$1" == "windows" ]]; then
        suffix='.exe'
    fi
    CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build -o "${RELEASE_BIN_DIR}vtun-$1_$2${suffix}" -ldflags "-w -s -X 'main._version=1.0.$(date +%Y%m%d)' -X 'main._goVersion=$(go version)' -X 'main._gitHash=$(git show -s --format=%H)' -X 'main._buildTime=$(git show -s --format=%cd)'" ./main.go
}

function main() {
    rm -rf $RELEASE_BIN_DIR
    go clean
    go mod tidy
    create_dir $RELEASE_BIN_DIR
    go_build linux 386
    go_build linux amd64
    go_build linux arm
    go_build linux arm64
    go_build darwin arm64
    go_build darwin amd64
    go_build windows 386
    go_build windows amd64
    go_build windows arm
    go_build windows arm64
}

main