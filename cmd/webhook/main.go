package main

import (
	"os"

	"github.com/aereal/enjoy-github-custom-deployment-protection-rules/webhook"
)

func main() {
	os.Exit(webhook.Start())
}
