package main

import (
	// comment out the services you don't need to make the compiled binary smaller.
	// _ "github.com/aagun1234/glider/service/xxx"

	// comment out the protocols you don't need to make the compiled binary smaller.
	_ "github.com/aagun1234/glider/proxy/http"
	_ "github.com/aagun1234/glider/proxy/kcp"
	_ "github.com/aagun1234/glider/proxy/mixed"
	_ "github.com/aagun1234/glider/proxy/obfs"
	_ "github.com/aagun1234/glider/proxy/pxyproto"
	_ "github.com/aagun1234/glider/proxy/reject"
	_ "github.com/aagun1234/glider/proxy/smux"
	_ "github.com/aagun1234/glider/proxy/socks4"
	_ "github.com/aagun1234/glider/proxy/socks5"
	_ "github.com/aagun1234/glider/proxy/ss"
	_ "github.com/aagun1234/glider/proxy/ssh"
	_ "github.com/aagun1234/glider/proxy/ssr"
	_ "github.com/aagun1234/glider/proxy/tcp"
	_ "github.com/aagun1234/glider/proxy/tls"
	_ "github.com/aagun1234/glider/proxy/trojan"
	_ "github.com/aagun1234/glider/proxy/udp"
	_ "github.com/aagun1234/glider/proxy/vless"
	_ "github.com/aagun1234/glider/proxy/vmess"
	_ "github.com/aagun1234/glider/proxy/ws"
)
