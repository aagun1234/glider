package main

import (
	// comment out the services you don't need to make the compiled binary smaller.
	_ "github.com/aagun1234/glider/service/dhcpd"

	// comment out the protocols you don't need to make the compiled binary smaller.
	_ "github.com/aagun1234/glider/proxy/redir"
	_ "github.com/aagun1234/glider/proxy/tproxy"
	_ "github.com/aagun1234/glider/proxy/unix"
	_ "github.com/aagun1234/glider/proxy/vsock"
)
