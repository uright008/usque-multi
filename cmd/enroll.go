package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
	"github.com/spf13/cobra"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enrolls a MASQUE private key and switches mode",
	Long: "Enrolls a MASQUE private key and switches mode. Useful for ZeroTier where IPv6 address can change." +
		" Or if you just want to deploy a new key.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			log.Fatalf("Failed to get config path: %v", err)
		}
		if configPath == "" {
			log.Fatalf("Config path is required")
		}

		deviceName, err := cmd.Flags().GetString("name")
		if err != nil {
			log.Fatalf("Failed to get device name: %v", err)
		}

		regenKey, err := cmd.Flags().GetBool("regen-key")
		if err != nil {
			log.Fatalf("Failed to get regen-key: %v", err)
		}

		log.Printf("Enrolling device key...")

		accountData := models.AccountData{
			Token: config.AppConfig.AccessToken,
			ID:    config.AppConfig.ID,
		}

		var (
			privKeyBytes []byte
			publicKey    []byte
		)

		if regenKey {
			log.Printf("Regenerating key pair...")
			privKeyBytes, publicKey, err = internal.GenerateEcKeyPair()
			if err != nil {
				log.Fatalf("Failed to generate key pair: %v", err)
			}
		} else {
			privKey, err := config.AppConfig.GetEcPrivateKey()
			if err != nil {
				log.Fatalf("Failed to get private key: %v", err)
			}

			publicKey, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				log.Fatalf("Failed to marshal public key: %v", err)
			}

			privKeyBytes, err = x509.MarshalECPrivateKey(privKey)
			if err != nil {
				log.Fatalf("Failed to marshal private key: %v", err)
			}
		}

		updatedAccountData, apiErr, err := api.EnrollKey(accountData, publicKey, deviceName)
		if err != nil {
			if apiErr != nil && apiErr.HasErrorMessage(models.InvalidPublicKey) {
				fmt.Print("Invalid public key detected. Regenerate key? (y/n): ")

				var response string
				if _, err := fmt.Scanln(&response); err != nil {
					log.Fatalf("Failed to read user input: %v", err)
				}

				if response == "y" {
					log.Printf("Regenerating key pair...")
					privKeyBytes, publicKey, err = internal.GenerateEcKeyPair()
					if err != nil {
						log.Fatalf("Failed to generate key pair: %v", err)
					}

					log.Println("Re-enrolling device key with new key pair...")
					updatedAccountData, apiErr, err = api.EnrollKey(accountData, publicKey, deviceName)
					if err != nil {
						if apiErr != nil {
							log.Fatalf("Failed to enroll key: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
						}
						log.Fatalf("Failed to enroll key: %v", err)
					}
				} else {
					log.Fatalf("Enrollment aborted by user. API errors: %s", apiErr.ErrorsAsString("; "))
				}
			} else {
				log.Fatalf("Failed to enroll key: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
			}
		}

		log.Printf("Successful registration. Saving config...")

		config.AppConfig = config.Config{
			PrivateKey: base64.StdEncoding.EncodeToString(privKeyBytes),
			// TODO: proper endpoint parsing in utils
			// strip :0
			EndpointV4: updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
			// strip [ from beginning and ]:0 from end
			EndpointV6:     updatedAccountData.Config.Peers[0].Endpoint.V6[1 : len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
			EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
			License:        updatedAccountData.Account.License,
			ID:             updatedAccountData.ID,
			AccessToken:    accountData.Token,
			IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
			IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
		}

		config.AppConfig.SaveConfig(configPath)

		log.Printf("Config saved to %s", configPath)
	},
}
