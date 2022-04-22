package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/froghub-io/kms/decrypt"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"path/filepath"
)

var ImportCmd = &cli.Command{
	Name:  "import",
	Usage: "Import KMS key config",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "repo-path",
			Usage:   "Specify the KMS configuration repository",
			EnvVars: []string{"KMS_REPO_PATH"},
			Value:   "/tmp",
		},
		&cli.StringFlag{
			Name:     "keyConfig",
			Usage:    "Input KMS key/secret config file path",
			Required: true,
		},
	},
	Action: func(cctx *cli.Context) error {
		repoPath := cctx.String("repo-path")
		kmsConfigPath := filepath.Join(repoPath, decrypt.KMSConfig)

		kmsKeys, err := decrypt.GetKmsKeys(kmsConfigPath)
		if err != nil {
			return err
		}

		keyConfigPath := cctx.String("keyConfig")
		ok, err := decrypt.FileExist(keyConfigPath)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("KMS key config is non-existent")
		}

		data, err := ioutil.ReadFile(keyConfigPath)
		if err != nil {
			return err
		}

		var keySecret = map[string]string{}
		err = json.Unmarshal(data, &keySecret)
		if err != nil {
			return err
		}

		kmsKeys[keySecret["kmsID"]] = keySecret["kmsKey"]

		b, err := json.MarshalIndent(kmsKeys, "", "")
		if err != nil {
			return err
		}
		reader := bytes.NewReader(b)

		err = decrypt.WriteFile(reader, kmsConfigPath)
		if err != nil {
			return err
		}

		return nil
	},
}
