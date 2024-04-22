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
		fmt.Printf("%v %T\n", cv, cv)
	}

	// Output:
	// 1 uint32
	// 2 uint32
	// 3 uint32
	// 4 uint32
	// 4294967295 uint32
}

func ExampleJwkSupportKeyAlg() {
	for _, v := range []ioconnect.JwkSupportKeyAlg{
		ioconnect.JwkSupportKeyAlg_Ed25519,
		ioconnect.JwkSupportKeyAlg_P256,
		ioconnect.JwkSupportKeyAlg_K256,
		100,
	} {
		cv := v.CEnum()
		fmt.Printf("%v %T\n", cv, cv)
	}

	// Output:
	// 0 uint32
	// 1 uint32
	// 2 uint32
	// 4294967295 uint32
}

func ExampleJwkLifetime() {
	for _, v := range []ioconnect.JwkLifetime{
		ioconnect.JwkLifetime_Volatile,
		ioconnect.JwkLifetime_Persistent,
	} {
		cv := v.CConst()
		fmt.Printf("0x%x %T\n", cv, cv)
	}

	// Output:
	// 0x0
	// 0x1
	// ioconnect._Ctype_int
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
