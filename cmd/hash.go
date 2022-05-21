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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"

	"github.com/spf13/cobra"
)

var algorythm string
var filePath string
var dataString string
var outputFile string

var inputFile string
var hashSumFile string

var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Hash allows you to create or verify hashes",
	Long: `
Hash command, makes hashing files easier and verifying hashes of files.
Just pass a flag and have fun.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Please use an appropriate command")
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)
	hashCmd.AddCommand(genCmd)
	hashCmd.AddCommand(verifyCmd)

	hashCmd.PersistentFlags().StringVarP(&algorythm, "algorythm", "a", "sha256", "Algorythm to use when hashing")

	genCmd.Flags().StringVarP(&dataString, "data", "d", "", "Data to be hashed")
	genCmd.Flags().StringVarP(&filePath, "file", "f", "", "File to be hashed")
	genCmd.Flags().StringVarP(&outputFile, "out", "o", "", "File to save the hashed output")

	verifyCmd.Flags().StringVarP(&inputFile, "file", "f", "", "File to be verified")
	verifyCmd.Flags().StringVarP(&hashSumFile, "hashSum", "s", "", "Hash sum to be checked")
}

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate the hash from string/file",
	Long: `
This subcommand generates hashes from strings and files.
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Generating Hash...")
		if dataString != "" {
			hash := hashString(dataString)
			if hash != "" {
				fmt.Println("Hashed String: ")
				fmt.Println(hash)
			} else {
				panic("Cannot find algorythm")
			}
		} else {
			if filePath != "" {
				if outputFile != "" {
					fmt.Println("Writing file1")
					writeFile(readFile(filePath), outputFile)
				} else {
					fileNameSplit := strings.Split(filePath, ".")
					fileName := fileNameSplit[0]
					fmt.Println("Writing file2")
					writeFile(readFile((filePath)), fileName+".hash")
				}
			} else {
				panic("User didn't specify string or file input")
			}
		}
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the hash from string/file",
	Long: `
This subcommand verifies file hash sums.
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Verifing Hash...")
		if inputFile != "" && hashSumFile != "" && algorythm != "" {
			fileHash := readFile(inputFile)
			hash := readFileRaw(hashSumFile)
			if fileHash == hash {
				fmt.Println("Hash verified successfully")
			} else {
				fmt.Println("Hash failed verification")
				fmt.Println("Provided hash: " + hash)
				fmt.Println("Calculated hash: " + fileHash)
				fmt.Println("Algorythm: " + algorythm)
			}
		} else {
			panic("Please enter input file, hash sum file and algorythm")
		}
	},
}

func hashString(data string) string {
	switch algorythm {
	case "sha256":
		hashedString := sha256.Sum256([]byte(data))
		return hex.EncodeToString(hashedString[:])
	case "sha512":
		hashedString := sha512.Sum512([]byte(data))
		return hex.EncodeToString(hashedString[:])
	case "md5":
		hashedString := md5.Sum([]byte(data))
		return hex.EncodeToString(hashedString[:])
	default:
		return ""
	}
}

func readFile(FilePath string) string {
	f, err := os.Open(FilePath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	switch algorythm {
	case "sha256":
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			panic(err)
		}
		return hex.EncodeToString(h.Sum(nil))

	case "sha512":
		h := sha512.New()
		if _, err := io.Copy(h, f); err != nil {
			panic(err)
		}
		return hex.EncodeToString(h.Sum(nil))

	case "md5":
		h := md5.New()
		if _, err := io.Copy(h, f); err != nil {
			panic(err)
		}
		return hex.EncodeToString(h.Sum(nil))

	default:
		panic("Cannot find algorythm")
	}
}

func writeFile(Data string, Name string) {
	if Data != "" {
		if err := os.WriteFile(Name, []byte(Data), 0666); err != nil {
			panic(err)
		}
	} else {
		panic("Cannot write null to file!")
	}
}

func readFileRaw(FilePath string) string {
	content, err := ioutil.ReadFile(FilePath)
	if err != nil {
		panic(err)
	}
	text := string(content)
	return text
}
