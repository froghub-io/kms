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

// Algorithm is a cryptographic algorithm that requires
// a cryptographic key.
type Algorithm string

const (
	// AlgorithmGeneric is a generic value that indicates
	// that the key can be used with multiple algorithms.
	AlgorithmGeneric Algorithm = ""

	// AES256_GCM_SHA256 is an algorithm that uses HMAC-SHA256
	// for key derivation and AES256-GCM for en/decryption.
	AES256_GCM_SHA256 Algorithm = "AES256-GCM_SHA256"

	// XCHACHA20_POLY1305 is an algorithm that uses HChaCha20
	// for key derivation and ChaCha20-Poly1305 for en/decryption.
	XCHACHA20_POLY1305 Algorithm = "XCHACHA20-POLY1305"
)

// String returns the Algorithm's string representation.
func (a Algorithm) String() string { return string(a) }

// KeySize returns the Algorithm's key size.
func (a Algorithm) KeySize() int {
	switch a {
	case AES256_GCM_SHA256:
		return 256 / 8
	case XCHACHA20_POLY1305:
		return 256 / 8
	case AlgorithmGeneric:
		return 256 / 8 // For generic/unknown keys, return 256 bit.
	default:
		return -1
	}
}
