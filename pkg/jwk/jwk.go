package jwk

type KeyOperation int

const (
	KeyOperationNone KeyOperation = iota
	KeyOperationSign
	KeyOperationVerify
	KeyOperationEncrypt
	KeyOperationDecrypt
	KeyOperationWrapKey
	KeyOperationUnWrapKey
	KeyOperationDeriveKey
	KeyOperationDeriveBits
)

type PublicKeyUse int

const (
	PubKeyUseNone PublicKeyUse = iota
	PubKeyUseSIG
	PubKeyUseENC
)

type Algorithm int

const (
	AlgorithmNone  Algorithm = iota
	AlgorithmHS256           // HMAC using SHA-256
	AlgorithmHS384
	AlgorithmHS512
	AlgorithmRS256 // RSASSA-PKCS1-v1_5 using SHA-256
	AlgorithmRS384
	AlgorithmRS512
	AlgorithmPS256 // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	AlgorithmPS384
	AlgorithmPS512
	AlgorithmEdDSA
	AlgorithmES256 // ECDSA using P-256 and SHA-256
	AlgorithmES384
	AlgorithmES256K
	AlgorithmES256KR
)

type Type int

const (
	TypeEC Type = iota + 1
	TypeRSA
	TypeSymmetric // rename oct
	TypeOKP
)

type ECParams struct {
	Curve         string // [12] rename "crv"
	CoordinateX   string // [48] rename "x"
	CoordinateY   string // [48] rename "x"
	EccPrivateKey string // [48] rename "": option
}

type RSAParams struct {
}

type SymmetricParams struct {
}

type OctetParams struct {
	Curve      string // char crv[12];           rename "crv"
	PublicKey  string // Base64url *public_key;  rename "x"
	PrivateKey string // Base64url *private_key; rename "d" : option
}

type JWK struct {
	PublicKeyUse         PublicKeyUse
	KeyOperation         KeyOperation
	KeyID                *uint
	X509URL              string
	X509CertificateChain string
	X509ThumbprintSHA1   string // [28]
	X509ThumbprintSHA256 string // [44]
	Algorithm            Algorithm
	Type                 Type
	EC                   *ECParams
	RSA                  *RSAParams
	Oct                  *SymmetricParams
	Opk                  *OctetParams
}
