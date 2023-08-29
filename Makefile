BUILDDIR=$(shell pwd)/bin/lib
IMPORT_PATH= \
	github.com/net-byte/vtun/mobile/config \
	github.com/net-byte/vtun/mobile/dtlsclient \
	github.com/net-byte/vtun/mobile/h1client \
	github.com/net-byte/vtun/mobile/h2client \
	github.com/net-byte/vtun/mobile/kcpclient \
	github.com/net-byte/vtun/mobile/quicclient \
	github.com/net-byte/vtun/mobile/tcpclient \
	github.com/net-byte/vtun/mobile/tlsclient \
	github.com/net-byte/vtun/mobile/utlsclient \
	github.com/net-byte/vtun/mobile/wsclient

all: ios android

ios: clean
	mkdir -p $(BUILDDIR)
	gomobile bind -o $(BUILDDIR)/vtun-lib.framework -a -ldflags '-w' -target=ios $(IMPORT_PATH)


android: clean
	mkdir -p $(BUILDDIR)
	env GO111MODULE="on" gomobile bind -o $(BUILDDIR)/vtun-lib.aar -a -v -x -androidapi 23 -ldflags '-w' -target=android $(IMPORT_PATH)

clean:
	gomobile clean
	rm -rf $(BUILDDIR)

cleanmodcache:
	go clean -modcache

test:
	go test ./...
