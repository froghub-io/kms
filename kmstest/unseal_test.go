package kmstest

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/froghub-io/kms/decrypt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestUnseal(t *testing.T) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	secretKey := "eyJieXRlcyI6InFxZUxPbDV6ZU9mdWQxWGVHSTZtbWd5QXRxOHFjeFNiRSt1TGRIK3dpR1E9IiwiYWxnb3JpdGhtIjoiWENIQUNIQTIwLVBPTFkxMzA1IiwiY3JlYXRlZF9hdCI6IjIwMjItMDQtMjBUMTA6MDA6MDcuNTIwMTg4WiIsImNyZWF0ZWRfYnkiOiIwMGI2ZWFlNzczZmQ2MzE0NzFkYjBkMzljMWU0Yzc4ZWU1ZTJlOGFkZWViOGUyMWNiZDQ1MWYyNzVkOTViNGE0In0="

	fsObjPath := "/Users/grw/Desktop/QmS3hZFEaR9SPN8Md7yxs3TG4No7vPnPmKLArfB78x77eF"
	readCloser, _, err := decrypt.FsOpenFile(context.TODO(), fsObjPath, 0)
	if err != nil {
		log.Error(err)
		return
	}
	defer readCloser.Close()

	data, err := ioutil.ReadAll(readCloser)
	metadataLen := decrypt.BytesToInt(data[0:4])
	log.Debug("metadataLen: ", metadataLen)

	var metadata map[string]string
	err = json.Unmarshal(data[4:4+metadataLen], &metadata)
	if err != nil {
		log.Error(err)
		return
	}
	log.Debug("metadata: ", metadata)

	reader := bytes.NewReader(data[4+metadataLen:])

	decReader, err := decrypt.Unseal(reader, metadata, secretKey)

	dest := filepath.Base(metadata[decrypt.MetaObject])

	err = decrypt.WriteFile(decReader, dest)
	if err != nil {
		log.Error(err)
		return
	}

	log.Info("Finish kms unseal")
}
