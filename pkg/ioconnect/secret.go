package ioconnect

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"

	"github.com/pkg/errors"
)

func NewJWKSecret() JWKSecret {
	s := JWKSecret{
		raw: make([]byte, 0, 32),
	}

	for i := 0; i < 32; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(128))
		if err != nil {
			panic(err)
		}
		_b := n.Bytes()
		if len(_b) == 0 {
			_b = []byte{0}
		}
		s.raw = append(s.raw, _b...)
	}
	return s
}

type JWKSecret struct {
	raw []byte
}

func (s *JWKSecret) Bytes() []byte {
	return s.raw
}

func (s *JWKSecret) IsZero() bool {
	return len(s.raw) == 0
}

func NewJWKSecretsFromBase64(str string) (JWKSecrets, error) {
	ss := JWKSecrets{}

	raw, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ss, errors.Wrap(err, "failed to decode jwk from base64")
	}
	if len(raw) != 64 {
		return ss, errors.New("invalid raw data length, expect 64 bytes")
	}
	ss[0].raw = append(ss[0].raw, raw[0:32]...)
	ss[1].raw = append(ss[1].raw, raw[32:]...)

	return ss, nil
}

func NewJWKSecrets() JWKSecrets {
	ss := JWKSecrets{}

	ss[0] = NewJWKSecret()
	ss[1] = NewJWKSecret()
	return ss
}

type JWKSecrets [2]JWKSecret

func (s JWKSecrets) String() string {
	raw := make([]byte, 64)
	copy(raw, s[0].raw)
	copy(raw[32:], s[1].raw)

	return base64.StdEncoding.EncodeToString(raw)
}

func (s JWKSecrets) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *JWKSecrets) UnmarshalText(data []byte) error {
	_s, err := NewJWKSecretsFromBase64(string(data))
	if err != nil {
		return err
	}
	*s = _s
	return nil
}
