package main

import (
	"os"

	"github.com/ramjac/gorc/internal/gorc"
)

func main() {
	os.Exit(gorc.Run(os.Args[1:], os.Stdout, os.Stderr))
}
