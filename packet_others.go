// +build !linux

package packet

func newHandler(iff string, c *Config) (Handler, error) {
	return nil, ErrNotImplemented
}

func init() {
	isOSSupported = false
}
