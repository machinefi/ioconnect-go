package commands

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func PrintJWK(cmd *cobra.Command, k *ioconnect.JWK, printSecret bool) {
	doc, _ := json.Marshal(k.Doc())
	cmd.Printf("did:     %s\n", k.DID())
	cmd.Printf("kid:     %s\n", k.KID())
	cmd.Printf("ka did:  %s\n", k.KeyAgreementDID())
	cmd.Printf("ka kid:  %s\n", k.KeyAgreementKID())
	if printSecret {
		cmd.Printf("secret:  %s\n", k.Export())
	}
	cmd.Printf("doc:     %s\n", string(doc))
}
