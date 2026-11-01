package xsig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"
)

func cert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour), IsCA: parent == nil, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if parent == nil {
		parent, parentKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func ask(h *Handler, der []byte) (int, []byte) {
	body := binary.LittleEndian.AppendUint16(nil, uint16(len(der)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", PathValidateCert, bytes.NewReader(append(body, der...))))
	return rec.Code, rec.Body.Bytes()
}

func TestValidateCert(t *testing.T) {
	ca, caKey := cert(t, "WLID CA", nil, nil)
	leaf, _ := cert(t, "login.live.com", ca, caKey)
	other, _ := cert(t, "other CA", nil, nil)
	calls := 0
	h := &Handler{CA: func(context.Context) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("xuacs down")
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), nil
	}}
	if st, _ := ask(h, leaf.Raw); st != 503 {
		t.Fatalf("CA unavailable answered %d", st)
	}
	st, b := ask(h, leaf.Raw)
	if st != 200 || len(b) != 12 || binary.LittleEndian.Uint32(b) != 0 || binary.LittleEndian.Uint64(b[4:]) == 0 {
		t.Fatalf("trusted: %d %x", st, b)
	}
	for _, der := range [][]byte{other.Raw, {9, 9, 9}} {
		if st, b := ask(h, der); st != 200 || binary.LittleEndian.Uint32(b) != hrCertUntrusted {
			t.Fatalf("untrusted: %d %x", st, b)
		}
	}
	if calls != 2 {
		t.Fatalf("CA fetched %d times", calls)
	}
}
