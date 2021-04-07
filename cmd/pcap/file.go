package main

import (
	"io"
	"os"
	"syscall"
	"unsafe"

	"github.com/urbanishimwe/packet"
)

// write packet data in PCAP format.
// See http://wiki.wireshark.org/Development/LibpcapFileFormat
// for information on the file format.
const (
	magicNanoseconds  uint32 = 0xA1B23C4D
	magicMicroseconds uint32 = 0xA1B2C3D4
	versionMajor      uint16 = 2
	versionMinor      uint16 = 4
	DLT_EN10MB               = 1
	DLT_RAW                  = 12
)

func initPcapFile(file string, c *packet.Config) (uintptr, error) {
	linktype := uint32(DLT_EN10MB)
	if c.NoLinkLayer {
		linktype = DLT_RAW
	}
	fd, err := syscall.Open(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return 0, err
	}
	var hdr [24]byte
	if c.TstampResolution == packet.TstampNano {
		*(*uint32)(unsafe.Pointer(&hdr)) = magicNanoseconds
	} else {
		*(*uint32)(unsafe.Pointer(&hdr)) = magicMicroseconds
	}
	*(*uint16)(unsafe.Pointer(&hdr[4])) = versionMajor
	*(*uint16)(unsafe.Pointer(&hdr[6])) = versionMinor
	*(*uint32)(unsafe.Pointer(&hdr[16])) = uint32(snap)
	*(*uint32)(unsafe.Pointer(&hdr[20])) = linktype
	n, err := write(uintptr(fd), unsafe.Pointer(&hdr), 24)
	if err != nil {
		syscall.Close(fd)
		return 0, err
	}
	if n < 24 {
		syscall.Close(fd)
		return 0, io.ErrShortWrite
	}
	return uintptr(fd), nil
}

func writePacketInfo(fd uintptr, i *packet.Info) error {
	var hdr [16]byte
	nano := i.Time.UnixNano()
	println(nano/1e9, nano%1e9)
	*(*uint32)(unsafe.Pointer(&hdr)) = uint32(nano / 1e9)
	*(*uint32)(unsafe.Pointer(&hdr[4])) = uint32(nano % 1e9)
	*(*uint32)(unsafe.Pointer(&hdr[8])) = uint32(i.CapLen)
	*(*uint32)(unsafe.Pointer(&hdr[12])) = uint32(i.Len)
	n, err := write(fd, unsafe.Pointer(&hdr), 16)
	if err != nil {
		return err
	}
	if n < 16 {
		return io.ErrShortWrite
	}
	return nil
}

func writePacketData(fd uintptr, buf []byte) error {
	n, err := write(fd, unsafe.Pointer(&buf[0]), len(buf))
	if err != nil {
		return err
	}
	if n < len(buf) {
		return io.ErrShortWrite
	}
	return nil
}

func write(fd uintptr, b unsafe.Pointer, len int) (int, error) {
	n, _, e := syscall.Syscall(syscall.SYS_WRITE, fd, uintptr(b), uintptr(len))
	if e == 0 {
		return int(n), nil
	}
	return int(n), e
}
