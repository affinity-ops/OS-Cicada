// Quick utility to mint a test EVAR for k6 load testing.
package main

import (
	"fmt"
	"os"

	"github.com/asai/cicada/sentry/internal/auth"
)

func main() {
	if err := auth.InitializeGatewayAuthority(); err != nil {
		fmt.Fprintf(os.Stderr, "Init failed: %v\n", err)
		os.Exit(1)
	}
	token, err := auth.MintEVARToken(auth.AgentSpecification{
		AgentID:       "77d370b2-544f-44f7-b583-a3f300dc9a43",
		TenantID:      "00000000-0000-0000-0000-000000000001",
		Scopes:        []string{"proxy:call", "llm:proxy"},
		ModelIntended: "gpt-4",
		CodeHash:      "k6-load-test-hash",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Mint failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(token)
}
