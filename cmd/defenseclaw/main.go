package main

import "github.com/defenseclaw/defenseclaw/internal/cli"

var version = "dev"

func main() {
	cli.SetVersion(version)
	cli.Execute()
}
