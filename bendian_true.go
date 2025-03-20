//go:build armbe || arm64be || m68k || mips || mips64 || mips64p32 || ppc || ppc64 || s390 || s390x || shbe || sparc || sparc64
// +build armbe arm64be m68k mips mips64 mips64p32 ppc ppc64 s390 s390x shbe sparc sparc64

// the above list of CPU archs was copied from https://github.com/golang/sys/blob/0cec03c779c1270924b29437a17b8a99ae590592/cpu/byteorder.go#L55
// Go may not support all of them! we list all of them just in case.

package packet

// convert from little endian to big endian
func htons(v uint16) uint16 {
	return v
}

func htonl(v uint32) uint32 {
	return v
}
