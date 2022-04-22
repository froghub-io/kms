package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/froghub-io/kms/decrypt"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"os"
	"path/filepath"
)

var InitCmd = &cli.Command{
	Name:  "init",
	Usage: "Initialize a KMS repo",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "repo-path",
			Usage:   "Specify the KMS configuration repository",
			EnvVars: []string{"KMS_REPO_PATH"},
			Value:   "/tmp",
		},
	},
	Action: func(cctx *cli.Context) error {
		log.Info("Initializing KMS")

		repoPath := cctx.String("repo-path")

		kmsConfigPath := filepath.Join(repoPath, decrypt.KMSConfig)

		ok, err := decrypt.FileExist(kmsConfigPath)
		if err != nil {
			return err
		}
		if ok {
			return fmt.Errorf("repo at '%s' is already initialized", decrypt.KMSConfig)
		}

		log.Infof("Initializing repo at '%s'", repoPath)
		err = os.MkdirAll(repoPath, 0755) //nolint: gosec
		if err != nil && !os.IsExist(err) {
			return err
		}

		c, err := os.Create(kmsConfigPath)
		if err != nil {
			return err
		}
		defer c.Close()
		err = os.Chmod(kmsConfigPath, 0666)
		if err != nil {
			return err
		}

		b, err := json.MarshalIndent(map[string]string{}, "", "")
		if err != nil {
			return fmt.Errorf("marshaling KMS config: %w", err)
		}

		if err := ioutil.WriteFile(kmsConfigPath, b, 0644); err != nil {
			return fmt.Errorf("persisting storage metadata (%s): %w", kmsConfigPath, err)
		}

		log.Infof("kms repo at '%s' initialized success", kmsConfigPath)

		return nil
	},
}
