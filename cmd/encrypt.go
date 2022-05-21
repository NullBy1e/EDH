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
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/spf13/cobra"
)

var algorythmName string
var outFile string
var inFile string
var plaintext string
var encryptionKey string
var passphrase string

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypts string/file",
	Long: `
Encrypt as the name suggest allows you to encrypt string or file.
You can use specific algorythms, keys and other cryptographic parameters to your liking.
Change the above by passing apropriate flag.`,
	Run: func(cmd *cobra.Command, args []string) {
		if algorythmName == "aes" {
			if encryptionKey == "" {
				if passphrase != "" {
					hash := sha256.Sum256([]byte(passphrase))
					encryptionKey = hex.EncodeToString(hash[:])
				} else {
					panic("Please provide key or a passphrase")
				}
			}
			if plaintext != "" {
				fmt.Println("Encryption Successful, hex:")
				fmt.Println(hex.EncodeToString(encryptString([]byte(plaintext))))
			} else {
				if inFile != "" && outFile != "" {
					fmt.Println("File mode")
					ciphertext := encryptString(readFileIn(inFile))
					writeFileOut(outFile, ciphertext)
				} else {
					panic("Please use input file and output file or pass appropriate file")
				}
			}
		} else if algorythmName == "rsa" {
			if encryptionKey != "" {
				f, err := ioutil.ReadFile(encryptionKey)
				if err != nil {
					panic(err)
				}

				publicKey, err := ParseRsaPublicKeyFromPemStr(string(f))
				if err != nil {
					panic(err)
				}

				if inFile != "" && outFile != "" {
					inFileRaw, err := ioutil.ReadFile(inFile)
					if err != nil {
						panic(err)
					}
					encryptedBytes, err := rsa.EncryptOAEP(
						sha256.New(),
						rand.Reader,
						publicKey,
						inFileRaw,
						nil)
					if err != nil {
						panic(err)
					}
					writeFileOut(outFile, encryptedBytes)
				} else if plaintext != "" {
					encryptedBytes, err := rsa.EncryptOAEP(
						sha256.New(),
						rand.Reader,
						publicKey,
						[]byte(plaintext),
						nil)
					if err != nil {
						panic(err)
					}
					fmt.Println(hex.EncodeToString(encryptedBytes))
				} else {
					panic("Please use apropriate flags")
				}
			} else {
				panic("Please provide a public key to encrypt message")
			}
		} else {
			panic("algorythm name not recognized")
		}
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	// * Defining flags to use
	encryptCmd.Flags().StringVarP(&algorythmName, "algorythm", "a", "aes", "Algorythm to use when encrypting")
	encryptCmd.Flags().StringVarP(&inFile, "inputFile", "f", "", "File input to use when encrypting")
	encryptCmd.Flags().StringVarP(&outFile, "outputFile", "o", "", "File output to use when encrypting")
	encryptCmd.Flags().StringVarP(&plaintext, "data", "d", "", "Data to encrypt")
	encryptCmd.Flags().StringVarP(&passphrase, "passphrase", "p", "", "Passphrase to use when encrypting")
	encryptCmd.Flags().StringVar(&encryptionKey, "key", "", "Key to use when encrypting")
}

func readFileIn(FilePath string) []byte {
	// * Reads file and returns byte array
	f, err := ioutil.ReadFile(FilePath)
	if err != nil {
		panic(err)
	}
	return f
}

func writeFileOut(FileName string, Data []byte) {
	if err := os.WriteFile(FileName, Data, 0666); err != nil {
		panic(err)
	}
}

func encryptString(Data []byte) []byte {
	// * Encrypt the byte array and return ciphertext as byte array
	switch algorythmName {
	case "aes":
		key, err := hex.DecodeString(encryptionKey)
		if err != nil {
			panic(err)
		}
		cphr, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		gcm, err := cipher.NewGCM(cphr)
		if err != nil {
			panic(err)
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			panic(err)
		}
		ciphertext := gcm.Seal(nonce, nonce, Data, nil)
		return ciphertext
	default:
		panic("Cannot find algorythm")
	}
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("key type is not rsa")
}
