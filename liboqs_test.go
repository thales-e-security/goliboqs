// Copyright 2019 Thales UK Limited
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package goliboqs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const libPath = "/usr/local/liboqs/lib/liboqs.so"

func TestRoundTrip(t *testing.T) {

	kems := []KemType{
		KemBike1L1,
		KemBike1L3,
		KemBike1L5,
		KemBike2L1,
		KemBike2L3,
		KemBike2L5,
		KemBike3L1,
		KemBike3L3,
		KemBike3L5,
		KemFrodo640AES,
		KemFrodo640Shake,
		KemFrodo976AES,
		KemFrodo976Shake,
		KemFrodo1344AES,
		KemFrodo1344Shake,
		KemNewHope512,
		KemNewHope1024,
		KemKyber512,
		KemKyber768,
		KemKyber1024,
		KemSidhP503,
		KemSidhP751,
		KemSikeP503,
		KemSikeP751,
	}

	k, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k.Close()) }()

	for _, kemAlg := range kems {
		t.Run(string(kemAlg), func(t *testing.T) {
			//t.Parallel() <-- cannot use this because https://github.com/stretchr/testify/issues/187

			testKEM, err := k.GetKem(kemAlg)
			if err == errAlgDisabledOrUnknown {
				t.Skipf("Skipping disabled/unknown algorithm %q", kemAlg)
			}
			require.NoError(t, err)
			defer func() { require.NoError(t, testKEM.Close()) }()

			publicKey, secretKey, err := testKEM.KeyPair()
			require.NoError(t, err)

			sharedSecret, ciphertext, err := testKEM.Encaps(publicKey)
			require.NoError(t, err)

			recoveredSecret, err := testKEM.Decaps(ciphertext, secretKey)
			require.NoError(t, err)

			assert.Equal(t, sharedSecret, recoveredSecret)
		})
	}
}

func TestBadLibrary(t *testing.T) {
	_, err := LoadLib("bad")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load module")
}

func TestReEntrantLibrary(t *testing.T) {
	k1, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k1.Close()) }()

	k2, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k2.Close()) }()
}

func TestLibraryClosed(t *testing.T) {
	k, err := LoadLib(libPath)
	require.NoError(t, err)
	require.NoError(t, k.Close())

	const expectedMsg = "library closed"

	t.Run("GetKEM", func(t *testing.T) {
		_, err := k.GetKem(KemBike1L1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), expectedMsg)
	})

	t.Run("Close", func(t *testing.T) {
		err := k.Close()
		require.Error(t, err)
		assert.Contains(t, err.Error(), expectedMsg)
	})
}

func TestKEMClosed(t *testing.T) {
	k, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k.Close()) }()

	testKEM, err := k.GetKem(KemKyber512)
	require.NoError(t, err)

	require.NoError(t, testKEM.Close())

	t.Run("KeyPair", func(t *testing.T) {
		_, _, err := testKEM.KeyPair()
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Encaps", func(t *testing.T) {
		_, _, err := testKEM.Encaps(nil)
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Decaps", func(t *testing.T) {
		_, err := testKEM.Decaps(nil, nil)
		assert.Equal(t, errAlreadyClosed, err)
	})

	t.Run("Decaps", func(t *testing.T) {
		err := testKEM.Close()
		assert.Equal(t, errAlreadyClosed, err)
	})
}

func TestInvalidKEMAlg(t *testing.T) {
	k, err := LoadLib(libPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, k.Close()) }()

	_, err = k.GetKem(KemType("this will never be valid"))
	assert.Equal(t, errAlgDisabledOrUnknown, err)
}

func TestLibErr(t *testing.T) {
	// Difficult to test this without a deliberately failing KEM library (which could
	// be a future idea...)

	err := libError(operationFailed, "test%d", 123)
	assert.EqualError(t, err, "test123")
}
