// Copyright (c) 2022 FrogHub, Inc.
//
// This file is part of FrogHub Files' Key Management Service Tools
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package decrypt

const (
	// MetaBucket is the s3 bucket name
	MetaBucket = "X-FrogHub-Internal-Bucket"

	// MetaObject is the s3 object name
	MetaObject = "X-FrogHub-Internal-Object"

	// MetaIV is the random initialization vector (IV) used for
	// the FrogHub-internal key derivation.
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
