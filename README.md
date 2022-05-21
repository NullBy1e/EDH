# EDH (Encryption, Decryption, Hashing)

Utility that aims to improve efficiency of encryption, decryption and hashing by making a simple to use CLI

Written in Go

## Installation Guide

Copy the Repo using `git clone https://github.com/cH3Ck-m8/EDH.git`

Install the Golang CLI package for your system ( macOS=>Homebrew, Debian=>apt etc.)

Enter the cloned repo `cd EDH`

Install the script using `go install`

After installation use the binary will be installed in `$HOME/go/bin`

Remember to add the `$HOME/go/bin folder` to the path or else you will have to pass the file location

Or you can just build the binary using `go build main.go`

On linux use `./main` from shell to run the binary

To use the guide below rename the main to EDH using `mv main EDH` and add it to the path

## Using the script

EDH has 4 main commands:
  - encrypt
  - decrypt
  - hash
  - genkeys

Each of them has its own flags you can check them by passing the `-h` or `--help` flag

For example running `EDH hash -h` will return all of the flags and description of what the command and flag does

Let's do a quick test:

By running  `EDH encrypt -p test123 -d ThisIsATest` we encrypt our string("ThisIsATest") with our passphrase("test123")

We get this hex string `91bace6bafd223f947fa69d4c996619ae05d8dc95b663804d9167cdb989eaa7bd9aa5d03fe5d1b`

If we want to decrypt it we will run `EDH decrypt -d 91bace6bafd223f947fa69d4c996619ae05d8dc95b663804d9167cdb989eaa7bd9aa5d03fe5d1b -p test123`

It will return `ThisIsATest`

That is a basic example of what this tool can do, so I encourage you to explore the script using the `-h` flag

