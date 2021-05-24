// +build 386 amd64 amd64p32 alpha arm arm64 mipsle mips64le mips64p32le nios2 ppc64le riscv riscv64 sh

// the above list of CPU archs was copied from https://github.com/golang/sys/blob/0cec03c779c1270924b29437a17b8a99ae590592/cpu/byteorder.go#L45
// Go may not support all of them! we list all of them just in case.

package packet

const isBigEndian bool = false
