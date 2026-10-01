// Go helper for Go ↔ Rust interoperability tests.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/hdmain/tcpduplex"
)

func main() {
	mode := flag.String("mode", "", "server|client")
	addr := flag.String("addr", "127.0.0.1:0", "listen or dial address")
	psk := flag.String("psk", "", "optional pre-shared key")
	msg := flag.String("msg", "hello-from-go", "payload")
	flag.Parse()

	cfg := tcpduplex.DefaultConfig()
	if *psk != "" {
		cfg.Handshake.PreSharedKey = []byte(*psk)
	}

	switch *mode {
	case "server":
		runServer(*addr, cfg, *msg)
	case "client":
		runClient(*addr, cfg, *msg)
	default:
		fmt.Fprintln(os.Stderr, "usage: -mode server|client -addr host:port")
		os.Exit(2)
	}
}

func runServer(addr string, cfg *tcpduplex.Config, expect string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fatal(err)
	}
	defer ln.Close()

	bound := ln.Addr().String()
	writeLenPrefixed(os.Stdout, []byte(bound))

	raw, err := ln.Accept()
	if err != nil {
		fatal(err)
	}
	conn, err := tcpduplex.ServeConnContext(context.Background(), raw, cfg)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	got, err := conn.Receive()
	if err != nil {
		fatal(err)
	}
	if string(got) != expect {
		fatal(fmt.Errorf("expected %q got %q", expect, got))
	}
	if err := conn.Send([]byte("ack-from-go")); err != nil {
		fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
}

func runClient(addr string, cfg *tcpduplex.Config, msg string) {
	conn, err := tcpduplex.DialContext(context.Background(), addr, cfg)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()
	if err := conn.Send([]byte(msg)); err != nil {
		fatal(err)
	}
	got, err := conn.Receive()
	if err != nil {
		fatal(err)
	}
	writeLenPrefixed(os.Stdout, got)
}

func writeLenPrefixed(w io.Writer, b []byte) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	_, _ = w.Write(hdr[:])
	_, _ = w.Write(b)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
