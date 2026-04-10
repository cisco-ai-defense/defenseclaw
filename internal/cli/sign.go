// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/signing"
)

var (
	signKeyFile    string
	signPublisher  string
	signOutputDir  string
	trustKeyFile   string
	trustName      string
	trustFP        string
	signOutputJSON bool
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign skills, MCPs, or plugins with an Ed25519 key",
	Long:  "Cryptographically sign DefenseClaw assets to establish publisher trust.",
}

var signKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 signing keypair",
	Long: `Generate a new Ed25519 keypair for signing skills, MCPs, and plugins.

Writes publisher.key (private) and publisher.pub (public) to the output directory.
Keep the private key secret. Distribute the public key to operators who need to
verify your signatures.`,
	RunE: runSignKeygen,
}

var signSkillCmd = &cobra.Command{
	Use:   "skill <path>",
	Short: "Sign a skill directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runSignSkill,
}

var signVerifyCmd = &cobra.Command{
	Use:   "verify <path>",
	Short: "Verify the signature of a skill, MCP, or plugin directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runSignVerify,
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage the trusted publisher store",
	Long:  "Add, list, or remove trusted publisher public keys.",
}

var trustAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a publisher public key to the trust store",
	RunE:  runTrustAdd,
}

var trustListCmd = &cobra.Command{
	Use:   "list",
	Short: "List trusted publishers",
	RunE:  runTrustList,
}

var trustRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a publisher from the trust store by fingerprint",
	RunE:  runTrustRemove,
}

func init() {
	signKeygenCmd.Flags().StringVar(&signOutputDir, "output", ".", "Directory to write keypair files")
	signSkillCmd.Flags().StringVar(&signKeyFile, "key", "", "Path to Ed25519 private key file")
	signSkillCmd.Flags().StringVar(&signPublisher, "publisher", "", "Publisher name")
	_ = signSkillCmd.MarkFlagRequired("key")
	_ = signSkillCmd.MarkFlagRequired("publisher")
	signVerifyCmd.Flags().BoolVar(&signOutputJSON, "json", false, "Output result as JSON")

	signCmd.AddCommand(signKeygenCmd)
	signCmd.AddCommand(signSkillCmd)
	signCmd.AddCommand(signVerifyCmd)
	rootCmd.AddCommand(signCmd)

	trustAddCmd.Flags().StringVar(&trustName, "name", "", "Publisher name")
	trustAddCmd.Flags().StringVar(&trustKeyFile, "key", "", "Path to Ed25519 public key file")
	_ = trustAddCmd.MarkFlagRequired("name")
	_ = trustAddCmd.MarkFlagRequired("key")
	trustRemoveCmd.Flags().StringVar(&trustFP, "fingerprint", "", "Publisher fingerprint to remove")
	_ = trustRemoveCmd.MarkFlagRequired("fingerprint")
	trustListCmd.Flags().BoolVar(&signOutputJSON, "json", false, "Output as JSON")

	trustCmd.AddCommand(trustAddCmd)
	trustCmd.AddCommand(trustListCmd)
	trustCmd.AddCommand(trustRemoveCmd)
	rootCmd.AddCommand(trustCmd)
}

func runSignKeygen(_ *cobra.Command, _ []string) error {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(signOutputDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	privPath := filepath.Join(signOutputDir, "publisher.key")
	pubPath := filepath.Join(signOutputDir, "publisher.pub")

	if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	fp := signing.Fingerprint(pub)
	fmt.Fprintf(os.Stderr, "Keypair generated:\n")
	fmt.Fprintf(os.Stderr, "  Private key: %s\n", privPath)
	fmt.Fprintf(os.Stderr, "  Public key:  %s\n", pubPath)
	fmt.Fprintf(os.Stderr, "  Fingerprint: %s\n", fp)
	return nil
}

func runSignSkill(_ *cobra.Command, args []string) error {
	dirPath := args[0]

	keyData, err := os.ReadFile(signKeyFile)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	keyHex := trimHex(string(keyData))
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid Ed25519 private key (expected %d bytes, got %d)", ed25519.PrivateKeySize, len(keyBytes))
	}
	priv := ed25519.PrivateKey(keyBytes)

	sig, err := signing.Sign(dirPath, priv, signPublisher)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Signed: %s\n", dirPath)
	fmt.Fprintf(os.Stderr, "  Publisher:    %s\n", sig.Publisher)
	fmt.Fprintf(os.Stderr, "  Fingerprint:  %s\n", sig.Fingerprint)
	fmt.Fprintf(os.Stderr, "  Content hash: %s\n", sig.ContentHash)
	fmt.Fprintf(os.Stderr, "  Signature:    %s\n", filepath.Join(dirPath, signing.SignatureFileName))
	return nil
}

func runSignVerify(_ *cobra.Command, args []string) error {
	dirPath := args[0]

	ts := loadTrustStore()
	var trusted []signing.Publisher
	if ts != nil {
		trusted = ts.List()
	}

	result, err := signing.Verify(dirPath, trusted)
	if err != nil {
		return err
	}

	if signOutputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	if result.Verified {
		fmt.Println("VERIFIED")
	} else if result.Signed {
		fmt.Println("SIGNED (not trusted)")
	} else {
		fmt.Println("UNSIGNED")
	}
	fmt.Printf("  Publisher:   %s\n", result.Publisher)
	fmt.Printf("  Fingerprint: %s\n", result.Fingerprint)
	fmt.Printf("  Reason:      %s\n", result.Reason)

	if auditLog != nil {
		_ = auditLog.LogAction("verify", dirPath, fmt.Sprintf(
			"signed=%t trusted=%t publisher=%s", result.Signed, result.Trusted, result.Publisher))
	}

	if auditStore != nil {
		name := filepath.Base(dirPath)
		_ = auditStore.SetSignatureStatus("skill", name, result.Publisher, result.Fingerprint, result.Verified, "", result.Reason)
	}

	return nil
}

func runTrustAdd(_ *cobra.Command, _ []string) error {
	ts := loadTrustStore()
	if ts == nil {
		return fmt.Errorf("trust store not configured")
	}

	keyData, err := os.ReadFile(trustKeyFile)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	keyHex := trimHex(string(keyData))

	pub, err := ts.Add(trustName, keyHex)
	if err != nil {
		return err
	}
	if err := ts.Save(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Added trusted publisher:\n")
	fmt.Fprintf(os.Stderr, "  Name:        %s\n", pub.Name)
	fmt.Fprintf(os.Stderr, "  Fingerprint: %s\n", pub.Fingerprint)

	if auditLog != nil {
		_ = auditLog.LogAction("trust-add", trustName, fmt.Sprintf("fingerprint=%s", pub.Fingerprint))
	}
	return nil
}

func runTrustList(_ *cobra.Command, _ []string) error {
	ts := loadTrustStore()
	if ts == nil {
		return fmt.Errorf("trust store not configured")
	}

	publishers := ts.List()

	if signOutputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(publishers)
	}

	if len(publishers) == 0 {
		fmt.Println("No trusted publishers.")
		return nil
	}

	fmt.Printf("%-20s %-64s %s\n", "NAME", "FINGERPRINT", "ADDED")
	for _, p := range publishers {
		fp := p.Fingerprint
		if len(fp) > 16 {
			fp = fp[:16] + "..."
		}
		fmt.Printf("%-20s %-64s %s\n", p.Name, fp, p.AddedAt)
	}
	return nil
}

func runTrustRemove(_ *cobra.Command, _ []string) error {
	ts := loadTrustStore()
	if ts == nil {
		return fmt.Errorf("trust store not configured")
	}

	if err := ts.Remove(trustFP); err != nil {
		return err
	}
	if err := ts.Save(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Removed publisher with fingerprint: %s\n", trustFP)

	if auditLog != nil {
		_ = auditLog.LogAction("trust-remove", trustFP, "publisher removed from trust store")
	}
	return nil
}

func loadTrustStore() *signing.TrustStore {
	trustDir := ""
	if cfg != nil {
		trustDir = cfg.Signing.TrustDir
	}
	if trustDir == "" {
		trustDir = filepath.Join(os.Getenv("HOME"), ".defenseclaw", "trust")
	}
	ts := signing.NewTrustStore(trustDir)
	_ = ts.Load()
	return ts
}

func trimHex(s string) string {
	s = filepath.Clean(s)
	// strip any whitespace/newlines
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			out = append(out, c)
		}
	}
	return string(out)
}
