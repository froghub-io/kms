package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/froghub-io/kms/decrypt"
	"github.com/urfave/cli/v2"
	"path/filepath"
)

var RemoveCmd = &cli.Command{
	Name:  "remove",
	Usage: "Remove KMS key ID",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "repo-path",
			Usage:   "Specify the KMS configuration repository",
			EnvVars: []string{"KMS_REPO_PATH"},
			Value:   "/tmp",
		},
		&cli.StringFlag{
			Name:     "keyID",
			Usage:    "Input KMS key ID",
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

		_, ok := kmsKeys[cctx.String("keyID")]
		if !ok {
			return errors.New("KMS key ID non-existent")
		}

		var tempKmsKeys = map[string]string{}
		for k, v := range kmsKeys {
			if k == cctx.String("keyID") {
				continue
			}
			tempKmsKeys[k] = v
		}
		b, err := json.MarshalIndent(tempKmsKeys, "", "")
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
