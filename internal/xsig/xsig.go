// Package xsig serves Xbox Live signatures and certificates (Live service 12,
// /xsig). Only ValidateCertificate is served so far. Moved out of x360-xuacs.
package xsig

// /xsig/ValidateCertificate.ashx (XRL 0xC0B). XAM's TLS provider checks only
// the name and dates of a Windows Live ID server's certificate itself, then
// pauses the handshake and asks Live whether the leaf is trusted (XNet SSL
// socket 0x81773940 -> FUN_81828FB0). A non-zero answer closes the socket
// without an alert (80151103 at the user logon).
//
// Request: u16 LE length | leaf DER. Reply (12 bytes): u32 LE HRESULT (0 =
// trusted) | u64 LE FILETIME until which XAM may cache the verdict for this
// leaf (keyed by its SHA-1). A leaf is trusted when the WLID TLS front's CA
// (x360-xuacs) signed it.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	PathValidateCert = "/xsig/ValidateCertificate.ashx"

	hrCertUntrusted = 0x80090325 // SEC_E_UNTRUSTED_ROOT
	certCacheTTL    = 24 * time.Hour
)

// Handler serves PathValidateCert. CA fetches the trusted CA's PEM; it is
// called until it succeeds once.
type Handler struct {
	CA  func(context.Context) ([]byte, error)
	Log *slog.Logger
	Now func() time.Time

	mu sync.Mutex
	ca *x509.Certificate
}

func (h *Handler) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) authority(ctx context.Context) (*x509.Certificate, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ca != nil || h.CA == nil {
		return h.ca, nil
	}
	p, err := h.CA(ctx)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("WLID CA: no PEM block")
	}
	if h.ca, err = x509.ParseCertificate(blk.Bytes); err != nil {
		return nil, err
	}
	return h.ca, nil
}

// fileTime converts to a Windows FILETIME (100 ns since 1601).
func fileTime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		return
	}
	if !strings.EqualFold(r.URL.Path, PathValidateCert) {
		h.log().Info("unhandled", "path", r.URL.Path)
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	ca, err := h.authority(r.Context())
	if err != nil {
		// Untrusted would close the console's sign-in for a day: fail the request instead.
		h.log().Error("WLID CA unavailable", "err", err)
		http.Error(w, "certificate authority unavailable", http.StatusServiceUnavailable)
		return
	}
	var der []byte
	if len(body) >= 2 {
		if n := int(binary.LittleEndian.Uint16(body)); len(body) >= 2+n {
			der = body[2 : 2+n]
		}
	}
	hr, exp := uint32(hrCertUntrusted), uint64(0)
	trusted := false
	if ca != nil && len(der) > 0 {
		if c, err := x509.ParseCertificate(der); err == nil && c.CheckSignatureFrom(ca) == nil {
			trusted = true
		}
	}
	if trusted {
		hr, exp = 0, fileTime(h.now().Add(certCacheTTL))
	}
	sum := sha256.Sum256(der)
	h.log().Info("validate certificate", "body_len", len(body), "der_len", len(der), "sha256", hex.EncodeToString(sum[:]), "trusted", trusted)
	out := binary.LittleEndian.AppendUint32(nil, hr)
	out = binary.LittleEndian.AppendUint64(out, exp)
	w.Header().Set("Content-Type", "xon/c")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.Write(out)
}
