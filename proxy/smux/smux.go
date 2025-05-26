package smux

import "github.com/aagun1234/glider/proxy"

func init() {
	proxy.AddUsage("smux", `
Smux scheme:
  smux://host:port
`)
}
