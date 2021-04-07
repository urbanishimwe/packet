# packet [![Go Reference](https://pkg.go.dev/badge/github.com/urbanishimwe/packet.svg)](https://pkg.go.dev/github.com/urbanishimwe/packet)

Package packet provides basic APIs for linux packet socket. MIT licensed.

It can be easily extended and (presumably) integrated with Go rutime poller.

```
go get github.com/urbanishimwe/packet
```

### Usage
The easiest way to use this library,

read packets,
```
import "github.com/urbanishimwe/packet"
   .............
   ...........
// create a handler
handler, err := packet.NewHander("", nil)
if err != nil {
    // handle errors
}

// read from handler
for {
    raw, info, err := handler.Read(true)
    if err == nil {
        usePacket(raw, info)
        continue
    }
    // check if error is recoverable
    if packet.Temporary(err) || packet.Timeout(err) {
        continue
    }
    // may be break!
}
```

send packets,
```
handler.Write([]byte, nil, packet.ProtoIP)
```

you can also use BPF filters and configurations to control the handler.

### PCAP
save packets in [pcap file format](https://github.com/urbanishimwe/packet/blob/master/cmd/pcap/pcap.go)
```
go build ./cmd/pcap
```

if you want to link with libpcap BPF expressions compiler use,
```
go build -tags=bpf ./cmd/pcap
```

### Stability

It is very unlikely that signatures and types exposed by this package will change but new APIs might be added. It is recommended to read documentation in order to use this library appropriately.
