SHELL=/usr/bin/env bash

all: build

unexport GOFLAGS

.PHONY: all build

TARGET=./kms

build:
	go mod tidy
	go build -o $(TARGET)

install:
	install -C $(TARGET) /usr/local/bin/kms

.PHONY: clean

clean:
	-rm -f $(TARGET)