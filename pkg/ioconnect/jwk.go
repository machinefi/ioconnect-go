package ioconnect

//#cgo CFLAGS: -I./include
//#include <ioconnect.h>
import "C"
import (
	"fmt"
	"github.com/pkg/errors"
	"unsafe"
)

func NewJWK(tpe JwkType, keyAlg JwkSupportKeyAlg, lifetime JwkLifetime, usage PsaKeyUsageType, alg PsaHashType, methods ...string) (*JWK, error) {
	key := &JWK{}
	key._ptr = C.iotex_jwk_generate(
		tpe.CEnum(),
		keyAlg.CEnum(),
		lifetime.CConst(),
		usage.CConst(),
		alg.CConst(),
		(*C.uint)(unsafe.Pointer(&key.id)),
	)
	if key._ptr == nil {
		return nil, errors.Errorf("failed to generate jwk")
	}

	key.dids = make(map[string]string)
	key.kids = make(map[string]string)
	for _, method := range methods {
		v := key.DID(method)
		if v == "" {
			return nil, errors.Errorf("failed to generate did, method: %s", method)
		}
		v = key.KID(method)
		if v == "" {
			return nil, errors.Errorf("failed to generate kid, method: %s", method)
		}
	}

	return key, nil
}

func NewMasterJWK(method ...string) (*JWK, error) {
	return NewJWK(
		JwkType_EC,
		JwkSupportKeyAlg_P256,
		JwkLifetime_Volatile,
		PsaKeyUsageType_SignHash|PsaKeyUsageType_VerifyHash|PsaKeyUsageType_Export,
		PsaHashType_SHA_256.PsaAlgorithmECDSA(),
		method...,
	)
}

func NewKeyAgreementJWK(method ...string) (*JWK, error) {
	return NewJWK(
		JwkType_EC,
		JwkSupportKeyAlg_P256,
		JwkLifetime_Volatile,
		PsaKeyUsageType_Derive,
		PsaAlgECDH,
		method...,
	)
}

type JWK struct {
	_ptr *C.JWK
	id   uint32
	dids map[string]string
	kids map[string]string
}

func (k *JWK) ID() uint32 { return k.id }

func (k *JWK) Type() JwkType {
	return 0
}

func (k *JWK) PrintFields() {
	fmt.Printf("public_key_use:          %v %T\n", k._ptr.public_key_use, k._ptr.public_key_use)
	fmt.Printf("key_options:             %v %T\n", k._ptr.key_operations, k._ptr.key_operations)
	fmt.Printf("key_id:                  %v %T\n", k._ptr.key_id, k._ptr.key_id)
	fmt.Printf("x509_url:                %v %T\n", k._ptr.x509_url, k._ptr.x509_url)
	fmt.Printf("x509_certificate_chain:  %v %T\n", k._ptr.x509_certificate_chain, k._ptr.x509_certificate_chain)
	fmt.Printf("x509_thumbprint_sha1:    %v %T\n", k._ptr.x509_thumbprint_sha1, k._ptr.x509_thumbprint_sha1)
	fmt.Printf("x509_thumbprint_sha256:  %v %T\n", k._ptr.x509_thumbprint_sha256, k._ptr.x509_thumbprint_sha256)
	fmt.Printf("alg:                     %v %T\n", k._ptr.alg, k._ptr.alg)
	fmt.Printf("type:                    %v %T\n", k._ptr._type, k._ptr._type)
	ec := *(*C.ECParams)(unsafe.Pointer(&k._ptr.Params))
	fmt.Printf("ec.crv:                  %v %T\n", ec.crv, ec.crv)
	fmt.Printf("ec.x_coordinate:         %v %T\n", ec.x_coordinate, ec.x_coordinate)
	fmt.Printf("ec.y_coordinate:         %v %T\n", ec.y_coordinate, ec.y_coordinate)
	fmt.Printf("ec.ecc_private_key:      %v %T\n", ec.ecc_private_key, ec.ecc_private_key)
}

func (k *JWK) DID(method string) string {
	v, ok := k.dids[method]
	if ok {
		return v
	}
	c := C.iotex_did_generate(C.CString(method), k._ptr)
	if c == nil {
		return ""
	}
	v = C.GoString(c)
	k.dids[method] = v
	return v
}

func (k *JWK) KID(method string) string {
	v, ok := k.kids[method]
	if ok {
		return v
	}
	c := C.iotex_jwk_generate_kid(C.CString(method), k._ptr)
	if c == nil {
		return ""
	}
	v = C.GoString(c)
	k.kids[method] = v
	return v
}

func (k *JWK) DIDDoc(method string, ka *JWK) {
}
