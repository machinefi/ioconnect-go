package ioconnect

import (
	"encoding/json"
	"time"
)

type Doc struct {
	Contexts           []string             `json:"@context"`
	ID                 string               `json:"id"` // master key
	Authentication     []string             `json:"authentication"`
	KeyAgreement       []string             `json:"keyAgreement"` // ka key
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
}

func (d *Doc) String() string {
	content, _ := json.Marshal(d)
	return string(content)
}

type VerificationMethod struct {
	ID                 string       `json:"id"`
	Type               string       `json:"type"`
	Controller         string       `json:"controller"`
	PublicKeyJwk       PublicKeyJWK `json:"publicKeyJwk"`
	PublicKeyMultibase string       `json:"publicKeyMultibase,omitempty"`
	PublicKeyBase58    string       `json:"publicKeyBase58,omitempty"`
}

type PublicKeyJWK struct {
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
}

type Controller struct {
	ID string `json:"id"`
}

func NewVerifiableCredentialByIssuerAndSubjectDIDs(issuer, subject string) *VerifiableCredential {
	return &VerifiableCredential{
		Contexts: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID:                "http://example.org/credentials/3731",
		Type:              []string{"VerifiableCredential"},
		CredentialSubject: []Controller{{ID: subject}},
		Issuer:            Controller{ID: issuer},
		IssuanceDate:      time.Now().Format(time.RFC3339),
	}
}

type VerifiableCredential struct {
	Contexts          []string     `json:"@context"`
	ID                string       `json:"id"`
	Type              []string     `json:"type"`
	CredentialSubject []Controller `json:"credentialSubject"`
	Issuer            Controller   `json:"issuer"`
	IssuanceDate      string       `json:"issuanceDate"`
}
