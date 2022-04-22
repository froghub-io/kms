package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/froghub-io/kms/decrypt"
	ipfsShell "github.com/ipfs/go-ipfs-api"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"net/http"
	"path"
	"path/filepath"
	"strings"
)

var DecryptCmd = &cli.Command{
	Name: "decrypt",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "repo-path",
			Usage:   "Specify the KMS configuration repository",
			EnvVars: []string{"KMS_REPO_PATH"},
			Value:   "/tmp",
		},
		&cli.StringFlag{
			Name:     "src",
			Usage:    "Specify encrypted file (support local file path, ipfs://file, https://file)",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "output",
			Usage: "Decrypted file output directory",
			Value: "",
		},
	},
	Action: func(cctx *cli.Context) error {
		repoPath := cctx.String("repo-path")
		kmsConfigPath := filepath.Join(repoPath, decrypt.KMSConfig)

		kmsKeys, err := decrypt.GetKmsKeys(kmsConfigPath)
		if err != nil {
			return err
		}

		src := cctx.String("src")
		var data []byte
		if strings.HasPrefix(src, "http") {
			resp, err := http.Get(src)
			if err != nil {
				return err
			}
			data, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
		} else if strings.HasPrefix(src, "ipfs") {
			str := strings.Replace(src, "ipfs://", "", 1)
			ss := strings.Split(str, "/")
			if len(ss) != 2 {
				return fmt.Errorf("src is not a valid ipfs link")
			}
			sh := ipfsShell.NewShell(ss[0])
			read, err := sh.Cat(ss[1])
			if err != nil {
				return err
			}
			data, err = ioutil.ReadAll(read)
			if err != nil {
				return err
			}
		} else {
			readCloser, _, err := decrypt.FsOpenFile(context.TODO(), src, 0)
			if err != nil {
				return err
			}
			defer readCloser.Close()
			data, err = ioutil.ReadAll(readCloser)
			if err != nil {
				return err
			}
		}

		metadataLen := decrypt.BytesToInt(data[0:4])
		log.Debug("metadataLen: ", metadataLen)

		var metadata map[string]string
		err = json.Unmarshal(data[4:4+metadataLen], &metadata)
		if err != nil {
			return err
		}
		log.Info("metadata: ", metadata)

		kmsID := metadata[decrypt.MetaKeyID]
		kmsKey, ok := kmsKeys[kmsID]
		if !ok {
			return errors.New("KMS key ID non-existent")
		}

		reader := bytes.NewReader(data[4+metadataLen:])
		decReader, err := decrypt.Unseal(reader, metadata, kmsKey)

		output := cctx.String("output")
		decrypt.MkdirAll(output)

		object := filepath.Base(metadata[decrypt.MetaObject])
		dest := ""
		if output != "" {
			dest = path.Join(output, object)
		} else {
			dest = object
		}

		err = decrypt.WriteFile(decReader, dest)
		if err != nil {
			return err
		}

		log.Info(dest)
		return nil
	},
}
