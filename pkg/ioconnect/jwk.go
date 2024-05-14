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

func NewJWKFromDoc(content []byte) (*JWK, error) {
	doc, err := NewDIDDoc(content)
	if err != nil {
		return nil, err
	}
	defer doc.Destroy()

	return doc.ParseJWK()
}

func newJWKBySecret(secret JWKSecret, tpe JwkType, keyAlg JwkSupportKeyAlg, lifetime JwkLifetime, usage PsaKeyUsageType, alg PsaHashType) (*JWK, error) {
	c_secret := (*C.uint8_t)(C.CBytes(secret.Bytes()))
	defer C.free(unsafe.Pointer(c_secret))

	k := &JWK{}
	k._ptr = C.iotex_jwk_generate_by_secret(
		c_secret,
		32,
		tpe.CEnum(),
		keyAlg.CEnum(),
		lifetime.CConst(),
		usage.CConst(),
		alg.CConst(),
		(*C.uint)(unsafe.Pointer(&k.id)),
	)
	if k._ptr == nil {
		return nil, errors.Errorf("failed to generate jwk by secret")
	}

	if err := k.init(); err != nil {
		return nil, err
	}

	return k, nil
}

func NewJWKBySecretBase64(secret string) (*JWK, error) {
	secrets, err := NewJWKSecretsFromBase64(secret)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new secret from string")
	}
	key, err := NewJWKBySecret(secrets)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate jwk from secrets")
	}
	return key, nil
}

func NewJWKBySecret(secrets JWKSecrets) (*JWK, error) {
	k, err := newJWKBySecret(
		secrets[0],
		JwkType_EC,
		JwkSupportKeyAlg_P256,
		JwkLifetime_Volatile,
		PsaKeyUsageType_SignHash|PsaKeyUsageType_VerifyHash|PsaKeyUsageType_Export,
		PsaHashType_SHA_256.PsaAlgorithmECDSA(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate master key")
	}

	ka, err := newJWKBySecret(
		secrets[1],
		JwkType_EC,
		JwkSupportKeyAlg_P256,
		JwkLifetime_Volatile,
		PsaKeyUsageType_Derive,
		PsaAlgECDH,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key agreement key")
	}
	k.ka = ka
	k.secrets = secrets

	if err = k.register(); err != nil {
		return nil, err
	}

	k.ka = ka
	return k, nil
}

func NewJWK() (*JWK, error) {
	secrets := NewJWKSecrets()

	return NewJWKBySecret(secrets)
}

type JWK struct {
	_ptr *C.JWK
	id   uint32
	did  string
	kid  string
	pk   *PublicKeyJWK
	ka   *JWK
	doc  *Doc

	secrets JWKSecrets
}

// register bind kid and JWK
func (k *JWK) register() error {
	kid := C.CString(k.ka.KID())
	defer C.free(unsafe.Pointer(kid))

	status := C.iotex_registry_item_register(kid, k.ka._ptr)
	if status < 0 {
		return errors.Errorf("failed to register ka kid")
	}
	return nil
}

func (k *JWK) init() error {
	if err := k.generateDID(); err != nil {
		return errors.Wrap(err, "failed to generate did")
	}
	if err := k.generateKID(); err != nil {
		return errors.Wrap(err, "failed to generate kid")
	}
	if err := k.generatePK(); err != nil {
		return errors.Wrap(err, "failed to generate public key")
	}
	return nil
}

func (k *JWK) generateDID() error {
	if k.did != "" {
		return nil
	}

	method := C.CString(MethodIO)
	defer C.free(unsafe.Pointer(method))

	did := C.iotex_did_generate(method, k._ptr)
	if did == nil {
		return errors.New("failed to generate did:io")
	}
	defer C.free(unsafe.Pointer(did))
	k.did = C.GoString(did)
	return nil
}

func (k *JWK) generateKID() error {
	if k.kid != "" {
		return nil
	}

	method := C.CString(MethodIO)
	defer C.free(unsafe.Pointer(method))

	kid := C.iotex_jwk_generate_kid(method, k._ptr)
	if kid == nil {
		return errors.New("failed to generate did:io#key")
	}
	defer C.free(unsafe.Pointer(kid))
	k.kid = C.GoString(kid)
	return nil
}

func (k *JWK) generatePK() error {
	if k.pk != nil {
		return nil
	}

	var ec *EC
	switch k.Type() {

	case JwkType_EC:
		// TODO if this union member need manual free ?
		ec = &EC{_ptr: *(*C.ECParams)(unsafe.Pointer(&k._ptr.Params))}
	default:
		return errors.Errorf("unsupported jwk parameter: [type: %d]", k.Type())
	}

	kid := ""
	if ec.Crv() == JwkSupportKeyAlg_P256.String() {
		kid = fmt.Sprintf("Key-p256-%d", k.id)
	} else {
		kid = fmt.Sprintf("Key-%s-%d", ec.Crv(), k.id)
	}
	k.pk = &PublicKeyJWK{
		Crv: ec.Crv(),
		X:   ec.X(),
		Y:   ec.Y(),
		Kty: k.Type().String(),
		Kid: kid,
	}
	return nil
}

func (k *JWK) ID() uint32 { return k.id }

func (k *JWK) Type() JwkType { return (JwkType)(k._ptr._type) }

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

func (k *JWK) DID() string { return k.did }

func (k *JWK) KID() string { return k.kid }

func (k *JWK) KeyAgreementDID() string {
	return k.ka.DID()
}

func (k *JWK) KeyAgreementKID() string {
	return k.ka.KID()
}

func (k *JWK) Doc() *Doc {
	if k.doc != nil {
		return k.doc
	}

	k.doc = &Doc{
		Contexts: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security#keyAgreementMethod",
		},
		ID:             k.DID(),
		KeyAgreement:   []string{k.ka.KID()},
		Authentication: []string{k.KID()},
		VerificationMethod: []VerificationMethod{
			{
				ID:           k.ka.KID(),
				Type:         "JsonWebKey2020",
				Controller:   k.DID(),
				PublicKeyJwk: *k.ka.pk,
			},
			{
				ID:           k.KID(),
				Type:         "JsonWebKey2020",
				Controller:   k.DID(),
				PublicKeyJwk: *k.pk,
			},
		},
	}

	return k.doc
}

func (k *JWK) SignToken(subject string) (string, error) {
	issuer := k.DID()
	vc := NewVerifiableCredentialByIssuerAndSubjectDIDs(issuer, subject)
	return k.SignTokenByVC(vc)
}

func (k *JWK) SignTokenByVC(vc *VerifiableCredential) (string, error) {
	c_issuer := C.CString(k.DID())
	defer C.free(unsafe.Pointer(c_issuer))

	data, err := json.Marshal(vc)
	if err != nil {
		return "", err
	}
	c_data := C.CString(string(data))
	defer C.free(unsafe.Pointer(c_data))

	handle := C.iotex_jwt_claim_new()
	if handle == nil {
		return "", errors.Errorf("failed to call C.iotex_jwt_claim_new, nil returned")
	}
	defer C.iotex_jwt_claim_destroy(handle)

	object := C.cJSON_Parse(c_data)
	if object == nil {
		return "", errors.Errorf("failed to call C.cJSON_Parse, nil returned")
	}
	defer C.cJSON_Delete(object)

	C.iotex_jwt_claim_set_value(handle, C.JWT_CLAIM_TYPE_ISS, nil, unsafe.Pointer(c_issuer))

	name := C.CString("vp")
	defer C.free(unsafe.Pointer(name))

	C.iotex_jwt_claim_set_value(handle, C.JWT_CLAIM_TYPE_PRIVATE_JSON, name, unsafe.Pointer(object))

	token := C.iotex_jwt_serialize(handle, C.JWT_TYPE_JWS, C.ES256, k._ptr)
	if token == nil {
		return "", errors.Errorf("failed to sign token")
	}
	defer C.free(unsafe.Pointer(token))

	return C.GoString(token), nil
}

func (k *JWK) VerifyToken(token string) (string, error) {
	ctoken := C.CString(token)
	defer C.free(unsafe.Pointer(ctoken))

	v := C.iotex_jwt_verify(ctoken, C.JWT_TYPE_JWS, C.ES256, k._ptr)
	if v == False.CConst() {
		return "", errors.Errorf("invalid token")
	}

	name := C.CString("vp")
	defer C.free(unsafe.Pointer(name))

	vp := C.iotex_jwt_claim_get_value(ctoken, C.JWT_TYPE_JWS, C.JWT_CLAIM_TYPE_PRIVATE_JSON, name)
	if vp == nil {
		return "", errors.Errorf("failed to get private vp")
	}
	defer C.cJSON_Delete((*C.cJSON)(unsafe.Pointer(vp)))

	vpser := C.cJSON_Print((*C.cJSON)(unsafe.Pointer(vp)))
	if vpser == nil {
		return "", errors.Errorf("failed to parse private vp")
	}
	defer C.free(unsafe.Pointer(vpser))

	vpcontent := C.GoString(vpser)
	vc := &VerifiableCredential{}

	if err := json.Unmarshal([]byte(vpcontent), vc); err != nil {
		return "", errors.Errorf("failed to parse private vp")
	}
	return vc.CredentialSubject[0].ID, nil
}

func (k *JWK) EncryptJSON(v any, recipient string) ([]byte, error) {
	if v == nil {
		return nil, errors.New("expect non-empty input `v`")
	}
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return k.Encrypt(plain, recipient)
}

func (k *JWK) Encrypt(plain []byte, recipient string) ([]byte, error) {
	// data := (*C.char)(C.CBytes(plain))
	// defer C.free(unsafe.Pointer(data))

	// alg := (C.enum_KWAlgorithms)(C.Ecdh1puA256kw)
	// enc := (C.enum_EncAlgorithm)(C.A256cbcHs512)
	// did := C.CString(k.DID()) // sender
	// defer C.free(unsafe.Pointer(did))

	// c_recipient := C.CString(recipient)
	// defer C.free(unsafe.Pointer(c_recipient))

	// recipients := [C.JOSE_JWE_RECIPIENTS_MAX]*C.char{c_recipient}

	// c := C.iotex_jwe_encrypt(data, alg, enc, did, k._ptr, &recipients[0], False.CConst())
	// if c == nil {
	// 	return nil, errors.Errorf("failed to encrypt data")
	// }
	// defer C.free(unsafe.Pointer(c))
	// cipher := C.GoString(c)
	// return []byte(cipher), nil
	return Encrypt(plain, k.DID(), recipient)
}

func (k *JWK) Decrypt(cipher []byte, sender string) ([]byte, error) {
	// data := (*C.char)(C.CBytes(cipher))
	// defer C.free(unsafe.Pointer(data))

	// alg := (C.enum_KWAlgorithms)(C.Ecdh1puA256kw)
	// enc := (C.enum_EncAlgorithm)(C.A256cbcHs512)
	// did := C.CString(sender) // sender
	// defer C.free(unsafe.Pointer(did))

	// recipient := C.CString(k.KeyAgreementKID())
	// defer C.free(unsafe.Pointer(recipient))

	// c := C.iotex_jwe_decrypt(data, alg, enc, did, nil, recipient)
	// if c == nil {
	// 	return nil, errors.Errorf("failed to decrypt data by sender did")
	// }
	// defer C.free(unsafe.Pointer(c))

	// plain := C.GoString(c)
	// return []byte(plain), nil
	return Decrypt(cipher, sender, k.KeyAgreementKID())
}

func (k *JWK) Export() JWKSecrets {
	return k.secrets
}

func (k *JWK) Destroy() {
	if k._ptr != nil {
		C.iotex_jwk_destroy(k._ptr)
		k._ptr = nil
	}
	if k.ka._ptr != nil {
		C.iotex_jwk_destroy(k.ka._ptr)
		k.ka._ptr = nil

		kid := C.CString(k.ka.KID())
		defer C.free(unsafe.Pointer(kid))
		C.iotex_registry_item_unregister(kid)
	}
}

func Encrypt(plain []byte, senderDID, recipientKaKID string) ([]byte, error) {
	data := (*C.char)(C.CBytes(plain))
	defer C.free(unsafe.Pointer(data))

	alg := (C.enum_KWAlgorithms)(C.Ecdh1puA256kw)
	enc := (C.enum_EncAlgorithm)(C.A256cbcHs512)
	did := C.CString(senderDID)
	defer C.free(unsafe.Pointer(did))

	c_recipient := C.CString(recipientKaKID)
	defer C.free(unsafe.Pointer(c_recipient))

	recipients := [C.JOSE_JWE_RECIPIENTS_MAX]*C.char{c_recipient}

	c := C.iotex_jwe_encrypt(data, alg, enc, did, nil, &recipients[0], False.CConst())
	if c == nil {
		return nil, errors.Errorf("failed to encrypt data")
	}
	defer C.free(unsafe.Pointer(c))
	cipher := C.GoString(c)
	return []byte(cipher), nil
}

func Decrypt(cipher []byte, senderDID, recipientKaKID string) ([]byte, error) {
	data := (*C.char)(C.CBytes(cipher))
	defer C.free(unsafe.Pointer(data))

	alg := (C.enum_KWAlgorithms)(C.Ecdh1puA256kw)
	enc := (C.enum_EncAlgorithm)(C.A256cbcHs512)
	did := C.CString(senderDID) // sender
	defer C.free(unsafe.Pointer(did))

	recipient := C.CString(recipientKaKID)
	defer C.free(unsafe.Pointer(recipient))

	c := C.iotex_jwe_decrypt(data, alg, enc, did, nil, recipient)
	if c == nil {
		return nil, errors.Errorf("failed to decrypt data")
	}
	defer C.free(unsafe.Pointer(c))

	plain := C.GoString(c)
	return []byte(plain), nil
}
