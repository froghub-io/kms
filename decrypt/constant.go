package decrypt

const KMSConfig = "kms-config.json"

const (
	// MetaBucket is the s3 bucket name
	MetaBucket = "X-FrogHub-Internal-Bucket"

	// MetaObject is the s3 object name
	MetaObject = "X-FrogHub-Internal-Object"

	// MetaIV is the random initialization vector (IV) used for
	// the MinIO-internal key derivation.
	MetaIV = "X-FrogHub-Internal-Server-Side-Encryption-Iv"

	// MetaAlgorithm is the algorithm used to derive internal keys
	// and encrypt the objects.
	MetaAlgorithm = "X-FrogHub-Internal-Server-Side-Encryption-Seal-Algorithm"

	// MetaSealedKeyKMS is the sealed object encryption key in case of SSE-KMS
	MetaSealedKeyKMS = "X-FrogHub-Internal-Server-Side-Encryption-Kms-Sealed-Key"

	// MetaKeyID is the KMS master key ID used to generate/encrypt the data
	// encryption key (DEK).
	MetaKeyID = "X-FrogHub-Internal-Server-Side-Encryption-S3-Kms-Key-Id"

	// MetaDataEncryptionKey is the sealed data encryption key (DEK) received from
	// the KMS.
	MetaDataEncryptionKey = "X-FrogHub-Internal-Server-Side-Encryption-S3-Kms-Sealed-Key"

	// ErrDecrypt is returned by a KES server when it fails to decrypt
	// a ciphertext. It may occur when a client uses the wrong key or
	// the ciphertext has been (maliciously) modified.
	KesErrDecrypt = "decryption failed: ciphertext is not authentic"
)

const (
	errInvalidArgument              = "invalid arguments specified"
	errIsNotRegular                 = "not of regular file type"
	errMissingInternalIV            = "the object metadata is missing the internal encryption IV"
	errMissingInternalSealAlgorithm = "the object metadata is missing the internal seal algorithm"
	errInvalidInternalIV            = "the internal encryption IV is malformed"
	errMissingInternalSealSSEKMS    = "the object metadata is missing the internal sealed key for SSE-KMS"
	errInvalidInternalSSEKMS        = "the internal sealed key for SSE-KMS is invalid"
)
