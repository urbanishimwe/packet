package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	"github.com/urbanishimwe/packet"
)

var (
	conf              *packet.Config
	iff, expr         string
	pcapFile, cpuProf string
	sig               chan os.Signal
	snap              int
)

func init() {
	conf = packet.DefaultConfig()
	flag.StringVar(&iff, "i", "", "interface name")
	flag.StringVar(&expr, "e", "", "attach bpf expression(require libpcap and to buuld with 'bpf' tag)")
	flag.IntVar(&snap, "snap", 256*1024, "snapshot length(used with -e)")
	flag.StringVar(&pcapFile, "f", "packet.pcap", "save packets in this pcap file")
	flag.Int64Var(&conf.ReadTimeout, "read-timeout", conf.ReadTimeout, "read timeout in milliseconds")
	flag.Int64Var(&conf.ReadBufferSize, "read-buffer", conf.ReadBufferSize, "read buffer size")
	flag.Int64Var(&conf.ReadBufferTimeout, "read-buffer-timeout", conf.ReadBufferTimeout, "read buffer timeout in milliseconds")
	flag.BoolVar(&conf.NonBlock, "non-block", conf.NonBlock, "enable non-blocking mode")
	flag.BoolVar(&conf.ImmediateMode, "immediate", conf.ImmediateMode, "enable immediate mode")
	flag.BoolVar(&conf.Promiscuous, "promisc", conf.NonBlock, "enable promiscuous mode")
	flag.BoolVar(&conf.NoLinkLayer, "cooked", conf.NoLinkLayer, "enable cooked mode(remove link layer header)")
	flag.Var((*proto)(&conf.Proto), "proto", "ethernet protocol(all, ip, ip6, arp)")
	flag.Var((*direction)(&conf.Direction), "direction", "packet flow(inout, in, out)")
	flag.Var((*tstampResolution)(&conf.TstampResolution), "resolution", "timestamp resolution(nano, micro)")
	flag.Uint64Var(&conf.MaxNilRead, "nil-read", conf.MaxNilRead, "max nil read")
	flag.StringVar(&cpuProf, "cpu-prof", "", "save cpu profile in this file")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "helper program to capture packets and save them in .pcap file format")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	setBPF()
	handler, err := packet.NewHandler(iff, conf)
	exitonError(err)
	fd, err := initPcapFile(pcapFile, handler.Config())
	exitonError(err)
	cpuProfile()
	go capture(fd, handler)
	sig = make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Printf("%#v\n", *handler.Stats(true))
	handler.Close()
	syscall.Close(int(fd))
	if cpuProf != "" {
		pprof.StopCPUProfile()
	}
}

func capture(fd uintptr, handler packet.Handler) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		buf, info, err := handler.Read(true)
		if err == nil {
			if err = writePacketInfo(fd, info); err == nil {
				err = writePacketData(fd, buf)
			}
			if err != nil {
				fmt.Fprint(os.Stderr, err)
			}
			continue
		}
		// check if error is recoverable
		if packet.Temporary(err) || packet.Timeout(err) {
			continue
		}
		fmt.Fprintln(os.Stderr, err)
		sig <- os.Interrupt
	}
}

func setBPF() {
	if expr == "" {
		return
	}
	linktype := packet.InterfaceLinkType(iff)
	if linktype != packet.LinkTypeEthernet {
		linktype = DLT_RAW
	}
	var err error
	conf.Filter, err = expr2Filter(expr, int(linktype))
	exitonError(err)
}

func cpuProfile() {
	if cpuProf == "" {
		return
	}
	f, err := os.Create(cpuProf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	pprof.StartCPUProfile(f)
}

func exitonError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

type direction packet.Direction

var _ flag.Value = new(direction)

func (d *direction) String() string {
	switch packet.Direction(*d) {
	case packet.DirInOut:
		return "inout"
	case packet.DirIn:
		return "in"
	case packet.DirOut:
		return "out"
	default:
		return fmt.Sprintf("<invalid:%d>", *d)
	}
}

// Set for this function to implement flag.Setter
func (d *direction) Set(v string) error {
	switch v {
	case "inout":
		*d = direction(packet.DirInOut)
	case "in":
		*d = direction(packet.DirIn)
	case "out":
		*d = direction(packet.DirOut)
	default:
		return syscall.EINVAL
	}
	return nil
}

type tstampResolution packet.TstampResolution

var _ flag.Value = new(tstampResolution)

func (t *tstampResolution) String() string {
	switch packet.TstampResolution(*t) {
	case packet.TstampNano:
		return "nano"
	case packet.TstampMicro:
		return "micro"
	default:
		return fmt.Sprintf("<invalid:%d>", *t)
	}
}

// Set for this function to implement flag.Setter
func (t *tstampResolution) Set(v string) error {
	switch v {
	case "nano":
		*t = tstampResolution(packet.TstampNano)
	case "micro":
		*t = tstampResolution(packet.TstampMicro)
	default:
		return syscall.EINVAL
	}
	return nil
}

type proto packet.Proto

var _ flag.Value = new(proto)

func (p *proto) String() string {
	switch packet.Proto(*p) {
	case packet.ProtoIP:
		return "ip"
	case packet.ProtoIP6:
		return "ip6"
	case packet.ProtoARP:
		return "arp"
	case packet.ProtoAll:
		return "all"
	default:
		return fmt.Sprintf("<invalid:%d>", *p)
	}
}

func (p *proto) Set(v string) error {
	switch v {
	case "ip":
		*p = proto(packet.ProtoIP)
	case "ip6":
		*p = proto(packet.ProtoIP6)
	case "arp":
		*p = proto(packet.ProtoARP)
	case "all":
		*p = proto(packet.ProtoAll)
	default:
		return syscall.EINVAL
	}
	return nil
}
