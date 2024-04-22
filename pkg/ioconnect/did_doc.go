package ioconnect

type DIDDoc struct {
	Contexts           []string             `json:"@context"`
	ID                 string               `json:"id"`           // master key
	KeyAgreement       []string             `json:"keyAgreement"` // ka key
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
}

type VerificationMethod struct {
	ID                 string       `json:"id"`
	Type               string       `json:"type"`
	Controller         string       `json:"controller"`
	PublicKeyJwk       PublicKeyJwk `json:"publicKeyJwk"`
	PublicKeyMultibase string       `json:"publicKeyMultibase,omitempty"`
	PublicKeyBase58    string       `json:"publicKeyBase58,omitempty"`
}

type PublicKeyJwk struct {
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
	Kty string `json:"kty"`
}
