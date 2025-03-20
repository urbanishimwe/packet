//go:build linux
// +build linux

package packet

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestBuildSlice(t *testing.T) {
	var b0 = []uint8{0xff, 0x98, 0xdc, 0x90}
	var b1 = buildSlice(unsafe.Pointer(&b0[0]), len(b0))
	if !bytes.Equal(b1, b0) {
		t.Errorf("%x should equal %x", b1, b0)
	}
}

func TestOffpointer(t *testing.T) {
	var b0 = []uint8{0xff, 0x98, 0xdc, 0x90}
	var b1 = buildSlice(
		offPointer(unsafe.Pointer(&b0[0]), 2),
		2,
	)
	if !bytes.Equal(b1, b0[2:]) {
		t.Errorf("%x should equal %x", b1, b0)
	}
}

func TestBswap16(t *testing.T) {
	const a = 0x80dd
	expect := [2]byte{0x80, 0xdd}
	got := htons(a)
	if *(*[2]byte)(unsafe.Pointer(&got)) != expect {
		t.Errorf("%x to equal %x", *(*[2]byte)(unsafe.Pointer(&got)), expect)
	}
}
