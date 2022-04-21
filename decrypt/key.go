// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MaxSize is the maximum byte size of an encoded key.
	MaxSize = 1 << 20

	// Size is the byte size of a cryptographic key.
	Size = 256 / 8

	// If FIPS-140 is enabled no non-NIST/FIPS approved
	// primitives must be used.
	Enabled = 0 == 1
)

// Adapted from Go stdlib.

var hexTable = "0123456789abcdef"

// EscapeStringJSON will escape a string for JSON and write it to dst.
func EscapeStringJSON(dst *bytes.Buffer, s string) {
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if htmlSafeSet[b] {
				i++
				continue
			}
			if start < i {
				dst.WriteString(s[start:i])
			}
			dst.WriteByte('\\')
			switch b {
			case '\\', '"':
				dst.WriteByte(b)
			case '\n':
				dst.WriteByte('n')
			case '\r':
				dst.WriteByte('r')
			case '\t':
				dst.WriteByte('t')
			default:
				// This encodes bytes < 0x20 except for \t, \n and \r.
				// If escapeHTML is set, it also escapes <, >, and &
				// because they can lead to security holes when
				// user-controlled strings are rendered into JSON
				// and served to some browsers.
				dst.WriteString(`u00`)
				dst.WriteByte(hexTable[b>>4])
				dst.WriteByte(hexTable[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				dst.WriteString(s[start:i])
			}
			dst.WriteString(`\ufffd`)
			i += size
			start = i
			continue
		}
		// U+2028 is LINE SEPARATOR.
		// U+2029 is PARAGRAPH SEPARATOR.
		// They are both technically valid characters in JSON strings,
		// but don't work in JSONP, which has to be evaluated as JavaScript,
		// and can lead to security holes there. It is valid JSON to
		// escape them, so we do so unconditionally.
		// See http://timelessrepo.com/json-isnt-a-javascript-subset for discussion.
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				dst.WriteString(s[start:i])
			}
			dst.WriteString(`\u202`)
			dst.WriteByte(hexTable[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		dst.WriteString(s[start:])
	}
}

// htmlSafeSet holds the value true if the ASCII character with the given
// array position can be safely represented inside a JSON string, embedded
// inside of HTML <script> tags, without any additional escaping.
//
// All values are true except for the ASCII control characters (0-31), the
// double quote ("), the backslash character ("\"), HTML opening and closing
// tags ("<" and ">"), and the ampersand ("&").
var htmlSafeSet = [utf8.RuneSelf]bool{
	' ':      true,
	'!':      true,
	'"':      false,
	'#':      true,
	'$':      true,
	'%':      true,
	'&':      false,
	'\'':     true,
	'(':      true,
	')':      true,
	'*':      true,
	'+':      true,
	',':      true,
	'-':      true,
	'.':      true,
	'/':      true,
	'0':      true,
	'1':      true,
	'2':      true,
	'3':      true,
	'4':      true,
	'5':      true,
	'6':      true,
	'7':      true,
	'8':      true,
	'9':      true,
	':':      true,
	';':      true,
	'<':      false,
	'=':      true,
	'>':      false,
	'?':      true,
	'@':      true,
	'A':      true,
	'B':      true,
	'C':      true,
	'D':      true,
	'E':      true,
	'F':      true,
	'G':      true,
	'H':      true,
	'I':      true,
	'J':      true,
	'K':      true,
	'L':      true,
	'M':      true,
	'N':      true,
	'O':      true,
	'P':      true,
	'Q':      true,
	'R':      true,
	'S':      true,
	'T':      true,
	'U':      true,
	'V':      true,
	'W':      true,
	'X':      true,
	'Y':      true,
	'Z':      true,
	'[':      true,
	'\\':     false,
	']':      true,
	'^':      true,
	'_':      true,
	'`':      true,
	'a':      true,
	'b':      true,
	'c':      true,
	'd':      true,
	'e':      true,
	'f':      true,
	'g':      true,
	'h':      true,
	'i':      true,
	'j':      true,
	'k':      true,
	'l':      true,
	'm':      true,
	'n':      true,
	'o':      true,
	'p':      true,
	'q':      true,
	'r':      true,
	's':      true,
	't':      true,
	'u':      true,
	'v':      true,
	'w':      true,
	'x':      true,
	'y':      true,
	'z':      true,
	'{':      true,
	'|':      true,
	'}':      true,
	'~':      true,
	'\u007f': true,
}

// MarshalText sorts the context keys and writes the sorted
// key-value pairs as canonical JSON object. The sort order
// is based on the un-escaped keys. It never returns an error.
func MarshalText(kmsCtx map[string]string) ([]byte, error) {
	if len(kmsCtx) == 0 {
		return []byte{'{', '}'}, nil
	}

	// Pre-allocate a buffer - 128 bytes is an arbitrary
	// heuristic value that seems like a good starting size.
	b := bytes.NewBuffer(make([]byte, 0, 128))
	if len(kmsCtx) == 1 {
		for k, v := range kmsCtx {
			b.WriteString(`{"`)
			EscapeStringJSON(b, k)
			b.WriteString(`":"`)
			EscapeStringJSON(b, v)
			b.WriteString(`"}`)
		}
		return b.Bytes(), nil
	}

	sortedKeys := make([]string, 0, len(kmsCtx))
	for k := range kmsCtx {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	b.WriteByte('{')
	for i, k := range sortedKeys {
		b.WriteByte('"')
		EscapeStringJSON(b, k)
		b.WriteString(`":"`)
		EscapeStringJSON(b, kmsCtx[k])
		b.WriteByte('"')
		if i < len(sortedKeys)-1 {
			b.WriteByte(',')
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// New returns an new Key for the given cryptographic algorithm.
// The key len must match algorithm's key size. The returned key
// is owned to the specified identity.
func New(algorithm Algorithm, key []byte, owner Identity) (Key, error) {
	if len(key) != algorithm.KeySize() {
		return Key{}, errors.New("key: invalid key size")
	}
	return Key{
		bytes:     clone(key...),
		algorithm: algorithm,
		createdAt: time.Now().UTC(),
		createdBy: owner,
	}, nil
}

// Random generates a new random Key for the cryptographic algorithm.
// The returned key is owned to the specified identity.
func Random(algorithm Algorithm, owner Identity) (Key, error) {
	key, err := randomBytes(algorithm.KeySize())
	if err != nil {
		return Key{}, err
	}
	return New(algorithm, key, owner)
}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Key is a symmetric cryptographic key.
type Key struct {
	bytes []byte

	algorithm Algorithm
	createdAt time.Time
	createdBy Identity
}

// Algorithm returns the cryptographic algorithm for which the
// key can be used.
func (k *Key) Algorithm() Algorithm { return k.algorithm }

// CreatedAt returns the point in time when the key has
// been created.
func (k *Key) CreatedAt() time.Time { return k.createdAt }

// CreatedBy returns the identity that created the key.
func (k *Key) CreatedBy() Identity { return k.createdBy }

// ID returns the k's key ID.
func (k *Key) ID() string {
	const Size = 128 / 8
	h := sha256.Sum256(k.bytes)
	return hex.EncodeToString(h[:Size])
}

// Clone returns a deep copy of the key.
func (k *Key) Clone() Key {
	return Key{
		bytes:     clone(k.bytes...),
		algorithm: k.Algorithm(),
		createdAt: k.CreatedAt(),
		createdBy: k.CreatedBy(),
	}
}

// Equal returns true if and only if both keys
// are identical.
func (k *Key) Equal(other Key) bool {
	if k.Algorithm() != other.Algorithm() {
		return false
	}
	return subtle.ConstantTimeCompare(k.bytes, other.bytes) == 1
}

// UnMarshalText parses and decodes text as encoded key.
func (k *Key) UnMarshalText(text []byte) error {
	type JSON struct {
		Bytes     []byte    `json:"bytes"`
		Algorithm Algorithm `json:"algorithm"`
		CreatedAt time.Time `json:"created_at"`
		CreatedBy Identity  `json:"created_by"`
	}
	var value JSON
	if err := json.Unmarshal(text, &value); err != nil {
		return err
	}
	k.bytes = value.Bytes
	k.algorithm = value.Algorithm
	k.createdAt = value.CreatedAt
	k.createdBy = value.CreatedBy
	return nil
}

// Unwrap decrypts the ciphertext and returns the
// resulting plaintext.
//
// It verifies that the associatedData matches the
// value used when the ciphertext has been generated.
func (k *Key) Unwrap(ciphertext, associatedData []byte) ([]byte, error) {
	text, err := decodeCiphertext(ciphertext)
	if err != nil {
		return nil, errors.New(KesErrDecrypt)
	}

	if text.ID != "" && text.ID != k.ID() { // Ciphertexts generated in the past may not contain a key ID
		return nil, errors.New(KesErrDecrypt)
	}
	if k.algorithm != "" && text.Algorithm != k.Algorithm() {
		return nil, errors.New(KesErrDecrypt)
	}

	cipher, err := newAEAD(text.Algorithm, k.bytes, text.IV)
	if err != nil {
		return nil, errors.New(KesErrDecrypt)
	}
	plaintext, err := cipher.Open(nil, text.Nonce, text.Bytes, associatedData)
	if err != nil {
		return nil, errors.New(KesErrDecrypt)
	}
	return plaintext, nil
}

// newAEAD returns a new AEAD cipher that implements the given
// algorithm and is initialized with the given key and iv.
func newAEAD(algorithm Algorithm, Key, IV []byte) (cipher.AEAD, error) {
	const (
		LEGACY_AES256_GCM_SHA256  = "AES-256-GCM-HMAC-SHA-256"
		LEGACY_XCHACHA20_POLY1305 = "ChaCha20Poly1305"
	)
	switch algorithm {
	case AES256_GCM_SHA256, LEGACY_AES256_GCM_SHA256:
		mac := hmac.New(sha256.New, Key)
		mac.Write(IV)
		sealingKey := mac.Sum(nil)

		block, err := aes.NewCipher(sealingKey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case XCHACHA20_POLY1305, LEGACY_XCHACHA20_POLY1305:
		if Enabled {
			return nil, errors.New(KesErrDecrypt)
		}
		sealingKey, err := chacha20.HChaCha20(Key, IV)
		if err != nil {
			return nil, err
		}
		return chacha20poly1305.New(sealingKey)
	default:
		return nil, errors.New(KesErrDecrypt)
	}
}

func clone(b ...byte) []byte {
	c := make([]byte, 0, len(b))
	return append(c, b...)
}
