package ioconnect

import "C"

//#cgo CFLAGS: -I./include
//#include <ioconnect.h>
import "C"
import "unsafe"

var (
	UnknownEnum  = (uint32)(0xFFFFFFFF)
	UnknownConst = -1
)

type JwkType int

const (
	JwkType_EC JwkType = iota + 1
	JwkType_RSA
	JwkType_Symmetric // rename oct
	JwkType_OKP
)

func (v JwkType) CEnum() C.enum_JWKType {
	switch v {
	case JwkType_EC:
		return C.JWKTYPE_EC
	case JwkType_RSA:
		return C.JWKTYPE_RSA
	case JwkType_Symmetric:
		return C.JWKTYPE_Symmetric
	case JwkType_OKP:
		return C.JWKTYPE_OKP
	default:
		return *(*C.enum_JWKType)(unsafe.Pointer(&UnknownEnum))
	}
}

func (v JwkType) String() string {
	switch v {
	case JwkType_EC:
		return "EC"
	case JwkType_RSA:
		return "RSA"
	case JwkType_OKP, JwkType_Symmetric:
		return "OCT"
	default:
		return ""
	}
}

type JwkSupportKeyAlg int

const (
	JwkSupportKeyAlg_Ed25519 JwkSupportKeyAlg = iota + 0
	JwkSupportKeyAlg_P256
	JwkSupportKeyAlg_K256
)

func (v JwkSupportKeyAlg) CEnum() C.enum_JWKSupportKeyAlg {
	switch v {
	case JwkSupportKeyAlg_Ed25519:
		return C.JWK_SUPPORT_KEY_ALG_ED25519
	case JwkSupportKeyAlg_P256:
		return C.JWK_SUPPORT_KEY_ALG_P256
	case JwkSupportKeyAlg_K256:
		return C.JWK_SUPPORT_KEY_ALG_K256
	default:
		return *(*C.enum_JWKSupportKeyAlg)(unsafe.Pointer(&UnknownEnum))
	}
}

type JwkLifetime int

const (
	JwkLifetime_Volatile   JwkLifetime = 0x00
	JwkLifetime_Persistent             = 0x01
)

func (v JwkLifetime) CConst() C.int {
	switch v {
	case JwkLifetime_Volatile:
		return C.IOTEX_JWK_LIFETIME_VOLATILE
	case JwkLifetime_Persistent:
		return C.IOTEX_JWK_LIFETIME_PERSISTENT
	default:
		return *(*C.int)(unsafe.Pointer(&UnknownConst))
	}
}

type PsaKeyUsageType uint32

const (
	PsaKeyUsageType_Export           PsaKeyUsageType = 0x00000001
	PsaKeyUsageType_Copy                             = 0x00000002
	PsaKeyUsageType_Encrypt                          = 0x00000100
	PsaKeyUsageType_Decrypt                          = 0x00000200
	PsaKeyUsageType_SignMessage                      = 0x00000400
	PsaKeyUsageType_VerifyMessage                    = 0x00000800
	PsaKeyUsageType_SignHash                         = 0x00001000
	PsaKeyUsageType_VerifyHash                       = 0x00002000
	PsaKeyUsageType_Derive                           = 0x00004000
	PsaKeyUsageType_VerifyDerivation                 = 0x00008000
)

func (v PsaKeyUsageType) CConst() C.uint32_t {
	return *(*C.uint32_t)(unsafe.Pointer(&v))
}

type PsaHashType uint32

const (
	PsaHashType_NONE         PsaHashType = 0
	PsaHashType_MD5          PsaHashType = 0x02000003
	PsaHashType_RIPEMD160    PsaHashType = 0x02000004
	PsaHashType_SHA_1        PsaHashType = 0x02000005
	PsaHashType_SHA_224      PsaHashType = 0x02000008
	PsaHashType_SHA_256      PsaHashType = 0x02000009
	PsaHashType_SHA_384      PsaHashType = 0x0200000a
	PsaHashType_SHA_512      PsaHashType = 0x0200000b
	PsaHashType_SHA_512_224  PsaHashType = 0x0200000c
	PsaHashType_SHA_512_256  PsaHashType = 0x0200000d
	PsaHashType_SHA3_224     PsaHashType = 0x02000010
	PsaHashType_SHA3_256     PsaHashType = 0x02000011
	PsaHashType_SHA3_384     PsaHashType = 0x02000012
	PsaHashType_SHA3_512     PsaHashType = 0x02000013
	PsaHashType_SHAKE256_512 PsaHashType = 0x02000015
	PsaAlgECDH               PsaHashType = 0x09020000 // TODO move to a new type as psa algorithm
)

func (v PsaHashType) CConst() C.uint32_t {
	return *(*C.uint32_t)(unsafe.Pointer(&v))
}

func (v PsaHashType) PsaAlgorithmHmac() PsaHashType {
	return PsaHashType(C.PSA_ALG_HMAC_BASE | v.CConst()&C.PSA_ALG_HASH_MASK)
}

func (v PsaHashType) PsaAlgorithmECDSA() PsaHashType {
	return PsaHashType(C.PSA_ALG_ECDSA_BASE | v.CConst()&C.PSA_ALG_HASH_MASK)
}

type PsaAlgType uint32
