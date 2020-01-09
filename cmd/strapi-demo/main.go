/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edge-store/cmd/strapi-demo/createdemodata"
)

// For Demo you can verify the records by browsing /admin example : http://localhost:1337/admin/
func main() {
	rootCmd := &cobra.Command{
		Use: "strapi-demo",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(createdemodata.GetStartCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to run strapi-demo: %s", err.Error())
	}
}
