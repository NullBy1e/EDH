/*
Copyright © 2021 NullBy1e

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

var passphrase2 string

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypts string/file",
	Long: `
Decrypt as the name suggest allows you to decrypt string or file.
You need to specifiy the algorythm and key to decrypt string or file,
by passing the appropriate flag to the command
`,
	Run: func(cmd *cobra.Command, args []string) {
		if algorythmName == "aes" {
			if encryptionKey == "" {
				if passphrase == "" {
					hash := sha256.Sum256([]byte(passphrase2))
					encryptionKey = hex.EncodeToString(hash[:])
				} else {
					panic("Please provide key or a passphrase")
				}
			}
			if plaintext != "" {
				fmt.Println("Decrypted Successfully, hex:")
				plaintext2, err := hex.DecodeString(plaintext)
				if err != nil {
					panic(err)
				}
				fmt.Println(string(decryptString(plaintext2)))
			} else {
				if inFile != "" && outFile != "" {
					fmt.Println("File mode")
					ciphertext := decryptString(readFileIn(inFile))
					writeFileOut(outFile, ciphertext)
				} else {
					panic("Please use input file and output file")
				}
			}
		} else if algorythmName == "rsa" {
			if encryptionKey != "" {
				decryptString(nil)
			} else {
				panic("Please provide a private key to encrypt message")
			}
		} else {
			panic("algorythm name not recognized")
		}
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringVarP(&algorythmName, "algorythm", "a", "aes", "Algorythm to use when decrypting")
	decryptCmd.Flags().StringVarP(&inFile, "inputFile", "f", "", "File input to use when decrypting")
	decryptCmd.Flags().StringVarP(&outFile, "outputFile", "o", "", "File output to use when decrypting")
	decryptCmd.Flags().StringVarP(&plaintext, "data", "d", "", "Data to decrypt")
	decryptCmd.Flags().StringVarP(&passphrase2, "passphrase", "p", "", "Passphrase to use when decrypting")
	decryptCmd.Flags().StringVar(&encryptionKey, "key", "", "Key to use when decrypting")
}

func decryptString(ciphertext []byte) []byte {
	switch algorythmName {
	case "aes":
		// * This shit encrypts using AES by hand. yes
		key, err := hex.DecodeString(encryptionKey)
		if err != nil {
			panic(err)
		}
		c, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		gcmDecrypt, err := cipher.NewGCM(c)
		if err != nil {
			panic(err)
		}
		nonceSize := gcmDecrypt.NonceSize()
		if len(ciphertext) < nonceSize {
			panic(err)
		}
		nonce, encryptedMessage := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcmDecrypt.Open(nil, []byte(nonce), []byte(encryptedMessage), nil)
		if err != nil {
			panic(err)
		}
		return plaintext

	case "rsa":
		f, err := ioutil.ReadFile(encryptionKey)
		if err != nil {
			panic(err)
		}

		privateKey, err := ParseRsaPrivateKeyFromPemStr(string(f))
		if err != nil {
			panic(err)
		}

		if inFile != "" && outFile != "" {
			inFileRaw, err := ioutil.ReadFile(inFile)
			if err != nil {
				panic(err)
			}

			decryptedBytes, err := privateKey.Decrypt(nil, inFileRaw, &rsa.OAEPOptions{Hash: crypto.SHA256})
			if err != nil {
				panic(err)
			}
			writeFileOut(outFile, decryptedBytes)
		} else if plaintext != "" {
			decryptedBytes, err := privateKey.Decrypt(nil, []byte(plaintext), &rsa.OAEPOptions{Hash: crypto.SHA256})
			if err != nil {
				panic(err)
			}
			fmt.Println(string(decryptedBytes))
		} else {
			panic("Please use apropriate flags")
		}

		return nil
	default:
		panic("Cannot find algorythm")
	}
}
