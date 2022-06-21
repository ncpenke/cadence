package custom_test

import (
	"github.com/onflow/cadence/encoding/custom"
	"github.com/onflow/cadence/runtime/sema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSemaCodec(t *testing.T) {
	t.Parallel()

	testEncodeDecode := func(input sema.Type, expectedEncoding ...byte) {
		bytes, err := custom.EncodeSema(input)
		require.NoError(t, err, "encoding error")

		if expectedEncoding != nil {
			assert.Equal(t, expectedEncoding, bytes)
		}

		output, err := custom.DecodeSema(nil, bytes)
		require.NoError(t, err, "decoding error")

		assert.Equal(t, input, output, "decoded message differs from input")
	}

	t.Run("robert", func(t *testing.T) {
		typ := &sema.AddressType{}

		bytes, err := custom.EncodeSema(typ)
		require.NoError(t, err)

		assert.Equal(t, []byte{101}, bytes)
	})

	t.Run("AddressType", func(t *testing.T) {
		t.Parallel()
		testEncodeDecode(&sema.AddressType{}, byte(custom.EncodedSemaAddressType))
	})

	t.Run("SimpleType", func(t *testing.T) {
		typ := sema.VoidType

		bytes, err := custom.EncodeSema(typ)
		require.NoError(t, err)

		assert.Equal(t, byte(custom.EncodedSemaSimpleType), bytes[0])
		// TODO verify more of the encoded SimpleType
	})
}
