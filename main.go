package main

import (
	"github.com/froghub-io/kms/cmd"
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
		Usage:   "KMS Command provides decryption and key management, suitable for decrypting FrogFS encrypted files.",
		Version: BuildVersion,
		Commands: []*cli.Command{
			cmd.InitCmd,
			cmd.DecryptCmd,
			cmd.ListCmd,
			cmd.ImportCmd,
			cmd.RemoveCmd,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Warnf("%+v", err)
		return
	}
}
