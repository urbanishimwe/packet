// +build !bpf

package main

import (
	"errors"

	"golang.org/x/net/bpf"
)

func expr2Filter(expr string, linktype int) ([]bpf.RawInstruction, error) {
	return nil, errors.New("bpf not supported. use 'go build -tags=bpf ./cmd/pcap'")
}
