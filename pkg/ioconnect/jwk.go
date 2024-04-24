package ioconnect

//#cgo CFLAGS: -I./include
//#include <ioconnect.h>
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
)

// TODO generate JWK from DID doc
func JWKFromDIDDoc(doc *DIDDoc) (*JWK, error) {
	// iotex_diddoc_verification_method_get(doc, purpose) => index
	// iotex_diddoc_verification_method_get(doc, purpose, index) => JWK
	// idx := C.iotex_diddoc_verification_method_get(doc, C.)
	return nil, nil
}

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

	key.kas = make(map[string]*JWK)
	key.docs = make(map[string]*DIDDoc)
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
		JwkLifetime_Volatile, // TODO
		PsaKeyUsageType_SignHash|PsaKeyUsageType_VerifyHash|PsaKeyUsageType_Export,
		PsaHashType_SHA_256.PsaAlgorithmECDSA(),
		method...,
	)
}

func NewKeyAgreementJWK(method ...string) (*JWK, error) {
	return NewJWK(
		JwkType_EC,
		JwkSupportKeyAlg_P256,
		JwkLifetime_Volatile, // ?
		PsaKeyUsageType_Derive,
		PsaAlgECDH,
		method...,
	)
}

type JWK struct {
	_ptr *C.JWK
	id   uint32
	dids map[string]string  // dids method: did
	kids map[string]string  // kids method: kid
	kas  map[string]*JWK    // kas method: key agreement jwk
	docs map[string]*DIDDoc // docs method: DIDDocument
}

func (k *JWK) ID() uint32 { return k.id }

func (k *JWK) Type() JwkType {
	return (JwkType)(k._ptr._type)
}

func (k *JWK) Param() any {
	switch k.Type() {
	case JwkType_EC:
		return &EC{_ptr: *(*C.ECParams)(unsafe.Pointer(&k._ptr.Params))}
	// case JwkType_RSA:
	// case JwkType_Symmetric:
	// case JwkType_OKP:
	default:
		panic("unsupported")
		return nil
	}
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

func (k *JWK) KeyAgreement(method string) (*JWK, error) {
	if ka, ok := k.kas[method]; ok {
		return ka, nil
	}
	ka, err := NewKeyAgreementJWK(method)
	if err != nil {
		return nil, err
	}
	kakid := ka.KID(method)
	status := C.iotex_registry_item_register(C.CString(kakid), ka._ptr)
	if *(*C.int)(unsafe.Pointer(&status)) < 0 {
		return nil, errors.Errorf("failed to register ka kid")
	}

	k.kas[method] = ka
	return ka, nil
}

func (k *JWK) KeyAgreementDID(method string) string {
	ka, err := k.KeyAgreement(method)
	if err != nil {
		return ""
	}
	return ka.DID(method)
}

func (k *JWK) KeyAgreementKID(method string) string {
	ka, err := k.KeyAgreement(method)
	if err != nil {
		return ""
	}
	return ka.KID(method)
}

func (k *JWK) DIDDoc(method string) (*DIDDoc, error) {
	if doc, ok := k.docs[method]; ok {
		return doc, nil
	}

	ka, err := k.KeyAgreement(method)
	if err != nil {
		return nil, errors.Errorf("failed to create key agreement jwk")
	}

	ec, ok := k.Param().(*EC)
	if !ok {
		return nil, errors.Errorf("unsupported jwk parameter")
	}

	kid := ""
	if ec.Crv() == JwkSupportKeyAlg_P256.String() {
		kid = fmt.Sprintf("Key-p256-%d", k.id)
	} else {
		kid = fmt.Sprintf("Key-%s-%d", ec.Crv(), k.id)
	}

	doc := &DIDDoc{
		Contexts: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security#keyAgreementMethod",
		},
		ID:           k.DID(method),
		KeyAgreement: []string{ka.KID(method)},
		VerificationMethod: []VerificationMethod{{
			ID:         ka.KID(method),
			Type:       "JsonWebKey2020",
			Controller: k.DID(method),
			PublicKeyJwk: PublicKeyJwk{
				Crv: ec.Crv(),
				X:   ec.X(),
				Y:   ec.Y(),
				Kty: k.Type().String(),
				Kid: kid,
			},
		}},
	}
	k.docs[ka.DID(method)] = doc

	return doc, nil
}

func (k *JWK) SignToken(method string, subject *JWK) (string, error) {
	return k.SignTokenBySubject(subject.DID(method))
}

func (k *JWK) SignTokenBySubject(subject string) (string, error) {
	issuer := k.DID("io")
	vc := NewVerifiableCredentialByIssuerAndSubjectDIDs(issuer, subject)
	return k.SignTokenByVC(vc)
}

func (k *JWK) SignTokenByVC(vc *VerifiableCredential) (string, error) {
	issuer := k.DID("io")
	data, err := json.Marshal(vc)
	if err != nil {
		return "", err
	}

	handle := C.iotex_jwt_claim_new()
	object := C.cJSON_Parse(C.CString(string(data)))

	C.iotex_jwt_claim_set_value(handle, C.JWT_CLAIM_TYPE_ISS, nil, unsafe.Pointer(C.CString(issuer)))
	C.iotex_jwt_claim_set_value(handle, C.JWT_CLAIM_TYPE_PRIVATE_JSON, C.CString("vp"), unsafe.Pointer(object))

	token := C.iotex_jwt_serialize(handle, C.JWT_TYPE_JWS, C.ES256, k._ptr)
	if token == nil {
		return "", errors.Errorf("failed to sign token")
	}
	return C.GoString(token), nil
}

func (k *JWK) VerifyToken(token string) (string, error) {
	v := C.iotex_jwt_verify(C.CString(token), C.JWT_TYPE_JWS, C.ES256, k._ptr)
	if v == *(*C._Bool)(unsafe.Pointer(new(int))) {
		return "", errors.Errorf("invalid token")
	}
	return "todo_return_peer_did", nil
}

func (k *JWK) Encrypt(method string, plain []byte, recipient string) ([]byte, error) {
	data := (*C.char)(C.CBytes(plain))
	alg := (C.enum_KWAlgorithms)(C.Ecdh1puA256kw)
	enc := (C.enum_EncAlgorithm)(C.A256cbcHs512)
	did := C.CString(k.DID(method)) // sender

	// for
	recipients := [C.JOSE_JWE_RECIPIENTS_MAX]*C.char{C.CString(recipient)}

	c := C.iotex_jwe_json_serialize(data, alg, enc, did, k._ptr, &recipients[0])
	if c == nil {
		return nil, errors.Errorf("failed to encrypt data")
	}
	return C.GoBytes(unsafe.Pointer(c), (C.int)(C.strlen(c))), nil
}

func (k *JWK) Decrypt(method string, cipher []byte, sender *JWK) ([]byte, error) {
	data := (*C.char)(C.CBytes(cipher))
	alg := (C.enum_KWAlgorithms)(C.Ecdh1puA256kw)
	enc := (C.enum_EncAlgorithm)(C.A256cbcHs512)
	did := C.CString(sender.DID(method)) // sender
	recipient := C.CString(k.KeyAgreementKID(method))

	c := C.iotex_jwe_decrypt(data, alg, enc, did, sender._ptr, recipient)
	if c == nil {
		return nil, errors.Errorf("failed to decrypt data")
	}
	return C.GoBytes(unsafe.Pointer(c), (C.int)(C.strlen(c))), nil
}

func (k *JWK) DecryptBySenderDID(method string, cipher []byte, sender string) ([]byte, error) {
	data := (*C.char)(C.CBytes(cipher))
	alg := (C.enum_KWAlgorithms)(C.Ecdh1puA256kw)
	enc := (C.enum_EncAlgorithm)(C.A256cbcHs512)
	did := C.CString(sender) // sender
	recipient := C.CString(k.KeyAgreementKID(method))

	c := C.iotex_jwe_decrypt(data, alg, enc, did, nil, recipient)
	if c == nil {
		return nil, errors.Errorf("failed to decrypt data by sender did")
	}
	return C.GoBytes(unsafe.Pointer(c), (C.int)(C.strlen(c))), nil
}

type EC struct {
	_ptr C.ECParams
}

func (v *EC) Crv() string {
	c := (*C.char)(unsafe.Pointer(&v._ptr.crv[0]))
	return C.GoString(c)
}

func (v *EC) X() string {
	c := (*C.char)(unsafe.Pointer(&v._ptr.x_coordinate[0]))
	return C.GoString(c)
}

func (v *EC) Y() string {
	c := (*C.char)(unsafe.Pointer(&v._ptr.y_coordinate[0]))
	return C.GoString(c)
}

func (v *EC) EccPrivateKey() string {
	c := (*C.char)(unsafe.Pointer(&v._ptr.ecc_private_key[0]))
	return C.GoString(c)
}

type RSA struct {
	_ptr C.RSAParams
}

type Symmetric struct {
	_ptr C.SymmetricParams
}

type Oct struct {
	_ptr C.OctetParams
}
