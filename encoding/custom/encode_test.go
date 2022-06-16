package custom_test

import (
	"github.com/onflow/cadence/encoding/custom"
	"github.com/onflow/cadence/runtime/sema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncoding(t *testing.T) {
	t.Parallel()

	t.Run("robert", func(t *testing.T) {
		typ := &sema.AddressType{}

		bytes, err := custom.EncodeSema(typ)
		require.NoError(t, err)

		assert.Equal(t, []byte{101}, bytes)
	})

	t.Run("AddressType", func(t *testing.T) {
		typ := &sema.AddressType{}

		bytes, err := custom.EncodeSema(typ)
		require.NoError(t, err)

		assert.Equal(t, []byte{byte(custom.EncodedSemaAddressType)}, bytes)
	})

	t.Run("SimpleType", func(t *testing.T) {
		typ := sema.VoidType

		bytes, err := custom.EncodeSema(typ)
		require.NoError(t, err)

		assert.Equal(t, byte(custom.EncodedSemaSimpleType), bytes[0])
		// TODO verify more of the encoded SimpleType
	})
}