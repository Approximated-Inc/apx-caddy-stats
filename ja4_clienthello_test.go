package apxstats

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mholt/caddy-l4/modules/l4tls"
)

// ja4ViaStdlibHandshake writes a raw ClientHello record to a real crypto/tls
// server and returns the JA4 computed from the *tls.ClientHelloInfo the stdlib
// builds. GetConfigForClient fires before version negotiation, so this works
// even for hellos the handshake would later reject.
func ja4ViaStdlibHandshake(t *testing.T, record []byte) (string, error) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	var (
		mu   sync.Mutex
		ja4  string
		seen = make(chan struct{})
	)

	cfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			ja4 = ja4FromClientHello(hello)
			mu.Unlock()
			close(seen)
			return nil, errors.New("stop handshake: fingerprint captured")
		},
	}

	go func() { _ = tls.Server(server, cfg).Handshake() }()
	go func() { _, _ = client.Write(record) }()

	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		return "", errors.New("GetConfigForClient never fired")
	}

	mu.Lock()
	defer mu.Unlock()
	return ja4, nil
}

func TestJA4FromClientHello_matchesFoxIOVectors(t *testing.T) {
	if len(l4tls.JAVectors) == 0 {
		t.Fatal("no FoxIO vectors vendored — the parity test is meaningless")
	}

	checked := 0
	for _, v := range l4tls.JAVectors {
		if v.ExpectedJA4 == "" {
			continue
		}
		checked++
		t.Run(v.Name, func(t *testing.T) {
			hello, err := hex.DecodeString(v.ClientHello)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			// Frame the handshake message as a TLS record.
			rec := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)

			got, err := ja4ViaStdlibHandshake(t, rec)
			if err != nil {
				t.Fatalf("capture failed: %v", err)
			}
			if got != v.ExpectedJA4 {
				t.Errorf("JA4 mismatch\n got: %q\nwant: %q", got, v.ExpectedJA4)
			}
		})
	}

	if checked == 0 {
		t.Fatal("no vector carried an ExpectedJA4 — nothing was actually asserted")
	}
}

func TestJA4FromClientHello_nilIsEmpty(t *testing.T) {
	if got := ja4FromClientHello(nil); got != "" {
		t.Errorf("ja4FromClientHello(nil) = %q, want \"\"", got)
	}
}
