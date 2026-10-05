package uauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	algES256 = -7
	algEdDSA = -8
	algRS256 = -257
)

const flagUserPresent = 0x01

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func parseClientData(b []byte, typ, origin string) (clientData, error) {
	var cd clientData
	if err := json.Unmarshal(b, &cd); err != nil {
		return cd, fmt.Errorf("clientDataJSON: %w", err)
	}
	if cd.Type != typ {
		return cd, fmt.Errorf("clientDataJSON: type %q", cd.Type)
	}
	if cd.Origin != origin {
		return cd, fmt.Errorf("clientDataJSON: origin %q, expected %q", cd.Origin, origin)
	}
	return cd, nil
}

func checkAuthenticatorData(ad []byte, rpID string) error {
	if len(ad) < 37 {
		return errors.New("authenticatorData: too short")
	}
	h := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad[:32], h[:]) {
		return errors.New("authenticatorData: rpIdHash mismatch")
	}
	if ad[32]&flagUserPresent == 0 {
		return errors.New("authenticatorData: user not present")
	}
	return nil
}

func parsePublicKey(alg int, spki []byte) (crypto.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	ok := false
	switch alg {
	case algES256:
		_, ok = pub.(*ecdsa.PublicKey)
	case algRS256:
		_, ok = pub.(*rsa.PublicKey)
	case algEdDSA:
		_, ok = pub.(ed25519.PublicKey)
	default:
		return nil, fmt.Errorf("unsupported algorithm %d", alg)
	}
	if !ok {
		return nil, fmt.Errorf("key type %T does not match algorithm %d", pub, alg)
	}
	return pub, nil
}

func verifyAssertion(pk Passkey, authData, clientDataJSON, sig []byte) error {
	pub, err := parsePublicKey(pk.Alg, pk.Key)
	if err != nil {
		return err
	}
	cdh := sha256.Sum256(clientDataJSON)
	msg := append(append([]byte{}, authData...), cdh[:]...)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		d := sha256.Sum256(msg)
		if ecdsa.VerifyASN1(k, d[:], sig) {
			return nil
		}
	case *rsa.PublicKey:
		d := sha256.Sum256(msg)
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig) == nil {
			return nil
		}
	case ed25519.PublicKey:
		if ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}
