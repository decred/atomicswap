#!/bin/bash
# The script does automatic checking on a Go package and its sub-packages, including:
# 1. gofmt         (http://golang.org/cmd/gofmt/)
# 2. go vet        (http://golang.org/cmd/vet)
# 3. gosimple      (https://github.com/dominikh/go-simple)
# 4. unconvert     (https://github.com/mdempsky/unconvert)
# 5. ineffassign   (https://github.com/gordonklaus/ineffassign)
# 6. race detector (http://blog.golang.org/race-detector)
# 7. test coverage (http://blog.golang.org/cover)

# gometaling (github.com/alecthomas/gometalinter) is used to run each each
# static checker.

set -ex

export GO111MODULE=on
for i in $(ls -1 cmd)
do
	(cd cmd/$i && go build)

	# check linters
	(cd cmd/$i && \
	 env go mod vendor &&
	 env GO111MODULE=off golangci-lint run --disable-all --deadline=10m \
		--enable=gofmt \
		--enable=vet \
		--enable=gosimple \
		--enable=unconvert \
		--enable=ineffassign)
done || exit 1
