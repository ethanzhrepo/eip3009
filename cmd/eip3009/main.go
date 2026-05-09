package main

import (
	"os"

	"eip3009/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
