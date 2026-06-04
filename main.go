package main

import (
	"net/http"
	"os"
	"time"

	"github.com/json-iterator/go/extra"
	"github.com/mzz2017/gg/cmd"
	"github.com/mzz2017/gg/dialer/singbox"
)

func main() {
	extra.RegisterFuzzyDecoders()
	singbox.RegisterAll()

	http.DefaultClient.Timeout = 30 * time.Second
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
