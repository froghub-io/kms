package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"os"
)

// BuildVersion is the local build version
const BuildVersion = "1.0.0"

func main() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	app := &cli.App{
		Name:    "kms",
		Usage:   "Benchmark performance of lotus on your hardware",
		Version: BuildVersion,
		Commands: []*cli.Command{
			unsealCmd,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Warnf("%+v", err)
		return
	}
}
