package custom_test

import (
	"github.com/onflow/cadence/encoding/custom"
	"github.com/onflow/cadence/runtime/sema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func testEncodeDecode(
	t *testing.T,
	input sema.Type,
	expectedEncoding ...byte,
) ([]byte, sema.Type) {
	bytes, err := custom.EncodeSema(input)
	require.NoError(t, err, "encoding error")

	if expectedEncoding != nil {
		assert.Equal(t, expectedEncoding, bytes)
	}

	output, err := custom.DecodeSema(nil, bytes)
	require.NoError(t, err, "decoding error")

	assert.Equal(t, input, output, "decoded message differs from input")

	return bytes, output
}

func TestSemaCodecSimpleTypes(t *testing.T) {
	t.Parallel()

	type TestInfo struct {
		SimpleType *sema.SimpleType
		SubType    custom.EncodedSemaSimpleSubType
	}

	tests := []TestInfo{
		{sema.AnyType, custom.EncodedSemaSimpleSubTypeAnyType},
		{sema.AnyResourceType, custom.EncodedSemaSimpleSubTypeAnyResourceType},
		{sema.AnyStructType, custom.EncodedSemaSimpleSubTypeAnyStructType},
		{sema.BlockType, custom.EncodedSemaSimpleSubTypeBlockType},
		{sema.BoolType, custom.EncodedSemaSimpleSubTypeBoolType},
		{sema.CharacterType, custom.EncodedSemaSimpleSubTypeCharacterType},
		{sema.DeployedContractType, custom.EncodedSemaSimpleSubTypeDeployedContractType},
		{sema.InvalidType, custom.EncodedSemaSimpleSubTypeInvalidType},
		{sema.MetaType, custom.EncodedSemaSimpleSubTypeMetaType},
		{sema.NeverType, custom.EncodedSemaSimpleSubTypeNeverType},
		{sema.PathType, custom.EncodedSemaSimpleSubTypePathType},
		{sema.StoragePathType, custom.EncodedSemaSimpleSubTypeStoragePathType},
		{sema.CapabilityPathType, custom.EncodedSemaSimpleSubTypeCapabilityPathType},
		{sema.PublicPathType, custom.EncodedSemaSimpleSubTypePublicPathType},
		{sema.PrivatePathType, custom.EncodedSemaSimpleSubTypePrivatePathType},
		{sema.StorableType, custom.EncodedSemaSimpleSubTypeStorableType},
		{sema.StringType, custom.EncodedSemaSimpleSubTypeStringType},
		{sema.VoidType, custom.EncodedSemaSimpleSubTypeVoidType},
	}

	for _, typ := range tests {
		t.Run(typ.SimpleType.Name, func(t *testing.T) {
			testEncodeDecode(t, typ.SimpleType,
				byte(custom.EncodedSemaSimpleType),
				byte(typ.SubType),
			)
		})
	}
}

func TestSemaCodec(t *testing.T) {
	t.Parallel()

	t.Run("robert", func(t *testing.T) {
		typ := &sema.AddressType{}

		bytes, err := custom.EncodeSema(typ)
		require.NoError(t, err)

		assert.Equal(t, []byte{101}, bytes)
	})

	t.Run("AddressType", func(t *testing.T) {
		t.Parallel()
		testEncodeDecode(t, &sema.AddressType{}, byte(custom.EncodedSemaAddressType))
	})

	t.Run("SimpleType", func(t *testing.T) {
		t.Parallel()

		testEncodeDecode(
			t,
			sema.VoidType,
			byte(custom.EncodedSemaSimpleType),
			byte(custom.EncodedSemaSimpleSubTypeVoidType),
		)
	})
}
