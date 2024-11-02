package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

var version = ""

func main() {
	app := &cli.App{
		Name:      "just-encrypt-yaml",
		Usage:     "Encrypt or decrypt YAML files using RSA keys",
		ArgsUsage: "<file>",
		Suggest:   true,
		Version:   version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "key",
				Usage:    "Path to the private RSA key (for decryption) or certificate (for encryption)",
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "decrypt",
				Usage: "Decrypt the YAML file",
			},
			&cli.StringFlag{
				Name:  "out",
				Usage: "Path to the output file",
			},
		},
		Action: func(c *cli.Context) error {
			yamlFile := c.Args().Get(0)
			key := c.String("key")
			decrypt := c.Bool("decrypt")

			// Default output file name
			outputFile := c.String("out")
			if outputFile == "" {
				base := filepath.Base(yamlFile)
				ext := filepath.Ext(yamlFile)
				name := base[:len(base)-len(ext)] // Strip extension from filename
				if decrypt {
					outputFile = filepath.Join(filepath.Dir(yamlFile), name+"-decrypted"+ext)
				} else {
					outputFile = filepath.Join(filepath.Dir(yamlFile), name+"-sealed"+ext)
				}
			}

			input, err := os.Open(yamlFile)
			if err != nil {
				return fmt.Errorf("failed to open YAML file: %w", err)
			}
			defer input.Close()

			output, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer output.Close()

			if decrypt {
				privKey, err := LoadPrivateKey(key)
				if err != nil {
					return fmt.Errorf("failed to load private key: %w", err)
				}
				if err := DecryptYAML(input, output, privKey); err != nil {
					return fmt.Errorf("decryption failed: %w", err)
				}
				fmt.Println("Decryption successful. Output written to:", outputFile)
			} else {
				pubKey, err := LoadCertificate(key)
				if err != nil {
					return fmt.Errorf("failed to load public certificate: %w", err)
				}
				if err := EncryptYAML(input, output, pubKey); err != nil {
					return fmt.Errorf("encryption failed: %w", err)
				}
				fmt.Println("Encryption successful. Output written to:", outputFile)
			}
			return nil
		},
	}

	// Run the app
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
