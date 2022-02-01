#! /bin/bash

set -e

BUILD_TIME=$(date -u +%Y-%m-%d-%I:%M:%S)
export BUILD_TIME
# https://github.com/golang/go/issues/26492
go build -tags 'osusergo,netgo,static_build,sqlite_omit_load_extension' -ldflags "-X main.ServerBuildTime=$BUILD_TIME -extldflags '-static' -s -w" -o oscar
