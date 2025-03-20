//go:build 386 || amd64 || amd64p32 || alpha || arm || arm64 || mipsle || mips64le || mips64p32le || nios2 || ppc64le || riscv || riscv64 || sh
// +build 386 amd64 amd64p32 alpha arm arm64 mipsle mips64le mips64p32le nios2 ppc64le riscv riscv64 sh

// the above list of CPU archs was copied from https://github.com/golang/sys/blob/0cec03c779c1270924b29437a17b8a99ae590592/cpu/byteorder.go#L45
// Go may not support all of them! we list all of them just in case.

package packet

// convert from little endian to big
func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

// convert from little endian to big
func htonl(v uint32) uint32 {
	return uint32((v&0xff000000)>>24) |
		uint32((v&0x00ff0000)>>8) |
		uint32((v&0x0000ff00)<<8) |
		uint32((v&0x000000ff)<<24)
}
