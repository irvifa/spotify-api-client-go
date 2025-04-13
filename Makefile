PKG := github.com/irvifa/spotify-api-client-go
BINARY := spotify-api-client

.PHONY: test

.PHONY: test tidy clean

test:
	go test ./... -v

tidy:
	go mod tidy

clean:
	rm -rf bin/

fmt:
	go fmt ./...
