package ioconnect_test

import (
	"fmt"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func ExampleJwkType() {
	for _, v := range []ioconnect.JwkType{
		ioconnect.JwkType_EC,
		ioconnect.JwkType_RSA,
		ioconnect.JwkType_Symmetric,
		ioconnect.JwkType_OKP,
		100,
	} {
		cv := v.CEnum()
		fmt.Printf("%v %s %T\n", cv, v, cv)
	}

	// Output:
	// 1 EC uint32
	// 2 RSA uint32
	// 3 OCT uint32
	// 4 OCT uint32
	// 4294967295  uint32
}

func ExampleJwkSupportKeyAlg() {
	for _, v := range []ioconnect.JwkSupportKeyAlg{
		ioconnect.JwkSupportKeyAlg_Ed25519,
		ioconnect.JwkSupportKeyAlg_P256,
		ioconnect.JwkSupportKeyAlg_K256,
		100,
	} {
		cv := v.CEnum()
		fmt.Printf("%v %s %T\n", cv, v, cv)
	}

	// Output:
	// 0 Ed25519 uint32
	// 1 P-256 uint32
	// 2 secp256k1 uint32
	// 4294967295  uint32
}

func ExampleJwkLifetime() {
	for _, v := range []ioconnect.JwkLifetime{
		ioconnect.JwkLifetime_Volatile,
		ioconnect.JwkLifetime_Persistent,
		100,
	} {
		cv := v.CConst()
		fmt.Printf("%v %T\n", cv, cv)
	}

	// Output:
	// 0 ioconnect._Ctype_int
	// 1 ioconnect._Ctype_int
	// -1 ioconnect._Ctype_int
}

func ExamplePsaKeyUsageType() {
	final := ioconnect.PsaKeyUsageType(0)
	for _, v := range []ioconnect.PsaKeyUsageType{
		ioconnect.PsaKeyUsageType_Export,
		ioconnect.PsaKeyUsageType_Copy,
		ioconnect.PsaKeyUsageType_Encrypt,
		ioconnect.PsaKeyUsageType_Decrypt,
		ioconnect.PsaKeyUsageType_SignMessage,
		ioconnect.PsaKeyUsageType_VerifyMessage,
		ioconnect.PsaKeyUsageType_SignHash,
		ioconnect.PsaKeyUsageType_VerifyHash,
		ioconnect.PsaKeyUsageType_Derive,
		ioconnect.PsaKeyUsageType_VerifyDerivation,
	} {
		final |= v
	}

	fmt.Printf("0x%X\n", final.CConst())
	fmt.Printf("%T\n", final.CConst())

	// Output:
	// 0xFF03
	// ioconnect._Ctype_uint
}
