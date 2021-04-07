// +build bpf

package main

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/net/bpf"
)

/*
#cgo linux LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap.h>

// Some old versions of pcap don't define this constant.
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif
*/
import "C"

func expr2Filter(expr string, linktype int) (filter []bpf.RawInstruction, err error) {
	cptr := C.pcap_open_dead(C.int(linktype), C.int(snap))
	if cptr == nil {
		return nil, errors.New("libpcap: error opening dead capture")
	}
	defer C.pcap_close(cptr)
	var program C.struct_bpf_program
	defer C.pcap_freecode(&program)
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))
	if C.pcap_compile(cptr, &program, cexpr, 1, C.PCAP_NETMASK_UNKNOWN) < 0 {
		return nil, fmt.Errorf("libpcap: compile filters error(%q)", C.GoString(C.pcap_geterr(cptr)))
	}
	insns := unsafe.Pointer(program.bf_insns)
	sizeOfIns := int(C.sizeof_struct_bpf_insn)
	filter = make([]bpf.RawInstruction, int(program.bf_len))
	for i := range filter {
		ins := (*C.struct_bpf_insn)(unsafe.Pointer(uintptr(insns) + uintptr(i*sizeOfIns)))
		filter[i].Op = uint16(ins.code)
		filter[i].Jt = uint8(ins.jt)
		filter[i].Jf = uint8(ins.jf)
		filter[i].K = uint32(ins.k)
	}
	return
}
