#!/bin/bash
RELEASE_BIN_DIR='./bin/'
RELEASE_NAME='vtun'
PACKAGE_NAME='github.com/net-byte/vtun/common'

# create dir
function create_dir() {
    if [ ! -d $1 ];then
        mkdir $1
    fi
}

# build
function go_build() {
    suffix=''
    if [[ "$1" == "windows" ]]; then
        suffix='.exe'
    fi
    CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build -o "${RELEASE_BIN_DIR}${RELEASE_NAME}-$1_$2${suffix}" -ldflags "-w -s -X '${PACKAGE_NAME}.Version=1.0.$(date +%Y%m%d)' -X '${PACKAGE_NAME}.GoVersion=$(go version)' -X '${PACKAGE_NAME}.GitHash=$(git show -s --format=%H)' -X '${PACKAGE_NAME}.BuildTime=$(git show -s --format=%cd)'" ./main.go
}

# main
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