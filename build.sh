#! /bin/bash

set -e

export BUILD_TIME=`date -u +%Y-%m-%d-%I:%M:%S`
go build -i -ldflags "-X main.ServerBuildTime=$BUILD_TIME -s -w" -o oscar
