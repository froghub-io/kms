package decrypt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/minio/sio"
	"io"
	"os"
	"path"
)

func WriteFile(reader io.Reader, dest string) error {
	f, err := openFile(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	buf := make([]byte, 10240)
	for {
		n, err := reader.Read(buf)
		w.Write(buf[:n])
		w.Flush()
		if err == io.EOF {
			break
		}
	}
	return nil
}

func openFile(filename string) (*os.File, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return os.Create(filename)
	}
	return os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)
}

func Unseal(reader io.Reader, metadata map[string]string, secretKey string) (io.Reader, error) {
	_, kmsKey, sealedKey, err := parseMetadata(metadata)
	if err != nil {
		return nil, err
	}

	kmsCtx := map[string]string{}
	kmsCtx[metadata[MetaBucket]] = path.Join(metadata[MetaBucket], metadata[MetaObject])

	ctxBytes, err := MarshalText(kmsCtx)
	if err != nil {
		return nil, err
	}

	secretKeyText, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return nil, err
	}
	var key Key
	key.UnMarshalText(secretKeyText)
	plaintext, err := key.Unwrap(kmsKey, ctxBytes)
	if err != nil {
		return nil, err
	}

	objectEncryptionKey, err := unsealObjectKey(plaintext, sealedKey, metadata[MetaBucket], metadata[MetaObject])
	decReader, err := newDecryptReaderWithObjectKey(reader, objectEncryptionKey, 0)

	return decReader, nil
}

func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)
	var x int32
	binary.Read(bytesBuffer, binary.LittleEndian, &x)
	return int(x)
}

func unsealObjectKey(extKey []byte, sealedKey SealedKey, bucket, object string) ([]byte, error) {
	domain := "SSE-KMS"
	var key ObjectKey
	key.Unseal(extKey, sealedKey, domain, bucket, object)

	return key[:], nil
}

func newDecryptReaderWithObjectKey(client io.Reader, objectEncryptionKey []byte, seqNumber uint32) (io.Reader, error) {
	reader, err := sio.DecryptReader(client, sio.Config{
		Key:            objectEncryptionKey,
		SequenceNumber: seqNumber,
		CipherSuites:   cipherSuitesDARE(),
	})
	if err != nil {
		return nil, errors.New("The SSE-C client key is invalid")
	}
	return reader, nil
}

// Opens the file at given path, optionally from an offset. Upon success returns
// a readable stream and the size of the readable stream.
func FsOpenFile(ctx context.Context, readPath string, offset int64) (io.ReadCloser, int64, error) {
	if readPath == "" || offset < 0 {
		return nil, 0, errors.New(errInvalidArgument)
	}

	fr, err := os.Open(readPath)
	if err != nil {
		return nil, 0, err
	}

	// Stat to get the size of the file at path.
	st, err := fr.Stat()
	if err != nil {
		fr.Close()
		return nil, 0, err
	}

	// Verify if its not a regular file, since subsequent Seek is undefined.
	if !st.Mode().IsRegular() {
		fr.Close()
		return nil, 0, errors.New(errIsNotRegular)
	}

	// Seek to the requested offset.
	if offset > 0 {
		_, err = fr.Seek(offset, io.SeekStart)
		if err != nil {
			fr.Close()
			return nil, 0, err
		}
	}

	// Success.
	return fr, st.Size(), nil
}

// ParseMetadata extracts all SSE-KMS related values from the object metadata
// and checks whether they are well-formed. It returns the sealed object key
// on success. If the metadata contains both, a KMS master key ID and a sealed
// KMS data key it returns both. If the metadata does not contain neither a
// KMS master key ID nor a sealed KMS data key it returns an empty keyID and
// KMS data key. Otherwise, it returns an error.
func parseMetadata(metadata map[string]string) (keyID string, kmsKey []byte, sealedKey SealedKey, err error) {
	b64IV, ok := metadata[MetaIV]
	if !ok {
		return "", nil, SealedKey{}, errors.New(errMissingInternalIV)
	}
	algorithm, ok := metadata[MetaAlgorithm]
	if !ok {
		return "", nil, SealedKey{}, errors.New(errMissingInternalSealAlgorithm)
	}
	b64SealedKey, ok := metadata[MetaSealedKeyKMS]
	if !ok {
		return "", nil, SealedKey{}, errors.New("The object metadata is missing the internal sealed key for SSE-S3")
	}
	iv, err := base64.StdEncoding.DecodeString(b64IV)
	if err != nil || len(iv) != 32 {
		return "", nil, SealedKey{}, errors.New(errInvalidInternalIV)
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(b64SealedKey)
	if err != nil || len(encryptedKey) != 64 {
		return "", nil, SealedKey{}, errors.New(errInvalidInternalSSEKMS)
	}
	keyID, idPresent := metadata[MetaKeyID]
	b64KMSSealedKey, kmsKeyPresent := metadata[MetaDataEncryptionKey]
	if !idPresent && kmsKeyPresent {
		return "", nil, SealedKey{}, errors.New(errMissingInternalSealSSEKMS)
	}
	kmsKey, err = base64.StdEncoding.DecodeString(b64KMSSealedKey)
	if err != nil {
		return
	}
	sealedKey = SealedKey{}
	sealedKey.Algorithm = algorithm
	copy(sealedKey.IV[:], iv)
	copy(sealedKey.Key[:], encryptedKey)

	return keyID, kmsKey, sealedKey, nil
}
