package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/froghub-io/kms/decrypt"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"path/filepath"
)

var unsealCmd = &cli.Command{
	Name: "unseal",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "secret-key",
			Usage:    "Input secret key",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "src",
			Usage:    "Source file",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "dest",
			Usage: "Destination file",
		},
	},
	Action: func(cctx *cli.Context) error {
		log.Info("Start kms unseal")

		secretKey := cctx.String("secret-key")
		fsObjPath := cctx.String("src")
		readCloser, _, err := decrypt.FsOpenFile(context.TODO(), fsObjPath, 0)
		if err != nil {
			return err
		}
		defer readCloser.Close()

		data, err := ioutil.ReadAll(readCloser)
		metadataLen := decrypt.BytesToInt(data[0:4])
		log.Debug("metadataLen: ", metadataLen)

		var metadata map[string]string
		err = json.Unmarshal(data[4:4+metadataLen], &metadata)
		if err != nil {
			return err
		}
		log.Debug("metadata: ", metadata)

		reader := bytes.NewReader(data[4+metadataLen:])

		decReader, err := decrypt.Unseal(reader, metadata, secretKey)

		dest := filepath.Base(metadata[decrypt.MetaObject])
		if cctx.String("dest") != "" {
			dest = cctx.String("dest")
		}

		err = decrypt.WriteFile(decReader, dest)
		if err != nil {
			return err
		}

		log.Info("Finish kms unseal")
		return nil
	},
}
