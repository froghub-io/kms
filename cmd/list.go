package cmd

import (
	"github.com/froghub-io/kms/decrypt"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"path/filepath"
)

var ListCmd = &cli.Command{
	Name:  "list",
	Usage: "Show KMS keys list",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "repo-path",
			Usage:   "Specify the KMS configuration repository",
			EnvVars: []string{"KMS_REPO_PATH"},
			Value:   "/tmp",
		},
	},
	Action: func(cctx *cli.Context) error {
		repoPath := cctx.String("repo-path")
		kmsConfigPath := filepath.Join(repoPath, decrypt.KMSConfig)

		kmsKeys, err := decrypt.GetKmsKeys(kmsConfigPath)
		if err != nil {
			return err
		}

		for k, _ := range kmsKeys {
			log.Infof("%s\n", k)
		}

		return nil
	},
}
