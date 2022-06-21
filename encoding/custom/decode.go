/*
 * Cadence - The resource-oriented smart contract programming language
 *
 * Copyright 2019-2022 Dapper Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package custom

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/onflow/cadence/runtime/ast"
	"github.com/onflow/cadence/runtime/sema"
	"io"

	"github.com/onflow/cadence"
	"github.com/onflow/cadence/runtime/common"
)

// A Decoder decodes custom-encoded representations of Cadence values.
type Decoder struct {
	r           io.Reader
	buf         []byte
	memoryGauge common.MemoryGauge
	types       map[common.TypeID]*cadence.CompositeType
	// TODO abi defining component types too?
	//      might get this anyway from varying type specificity
	rootType cadence.Type
}

// Decode returns a Cadence value decoded from its custom-encoded representation.
//
// This function returns an error if the bytes represent a custom encoding that
// is malformed, does not conform to the custom Cadence specification, or contains
// an unknown composite type.
func Decode(gauge common.MemoryGauge, b []byte, rootType cadence.Type) (cadence.Value, error) {
	r := bytes.NewReader(b)
	dec := NewDecoder(gauge, r, rootType)

	v, err := dec.Decode()
	if err != nil {
		return nil, err
	}

	return v, nil
}

// NewDecoder initializes a Decoder that will decode custom-encoded bytes from the
// given io.Reader.
func NewDecoder(memoryGauge common.MemoryGauge, r io.Reader, rootType cadence.Type) *Decoder {
	return &Decoder{
		r:           r,
		memoryGauge: memoryGauge,
		rootType:    rootType,
	}
}

// Decode reads custom-encoded bytes from the io.Reader and decodes them to a
// Cadence value.
//
// This function returns an error if the bytes represent a custom encoding that
// is malformed, does not conform to the custom Cadence specification, or contains
// an unknown composite type.
func (d *Decoder) Decode() (value cadence.Value, err error) {
	// capture panics that occur during decoding
	defer func() {
		if r := recover(); r != nil {
			panicErr, isError := r.(error)
			if !isError {
				panic(r)
			}

			err = fmt.Errorf("failed to decode value: %w", panicErr)
		}
	}()

	t := d.rootType

	// Since type is not already known, try to read an encoded type.
	if t == nil {
		t, err = d.DecodeType()
		if err != nil {
			return
		}
	}

	return d.DecodeValue(t)
}

//
// Values
//

func (d *Decoder) DecodeValue(t cadence.Type) (value cadence.Value, err error) {
	switch actualType := t.(type) {
	case cadence.VoidType:
		value = cadence.NewMeteredVoid(d.memoryGauge)
	case cadence.BoolType:
		value, err = d.DecodeBool()
	case cadence.OptionalType:
		value, err = d.DecodeOptional()
	case cadence.ArrayType:
		value, err = d.DecodeArray(&actualType)
	}

	return
}

func (d *Decoder) DecodeVoid() (value cadence.Void, err error) {
	_, err = d.read(1)
	value = cadence.NewMeteredVoid(d.memoryGauge)
	return
}

func (d *Decoder) DecodeOptional() (value cadence.Optional, err error) {
	t, err := d.DecodeType()
	if err != nil {
		return
	}

	innerValue, err := d.DecodeValue(t)
	value = cadence.NewMeteredOptional(d.memoryGauge, innerValue)
	return
}

func (d *Decoder) DecodeBool() (value cadence.Bool, err error) {
	b, err := d.read(1)
	if err != nil {
		return
	}

	switch b[0] {
	case 0:
		value = cadence.NewMeteredBool(d.memoryGauge, false)
	case 1:
		value = cadence.NewMeteredBool(d.memoryGauge, true)
	default:
		err = fmt.Errorf("bool must be 0 or 1 not: %d", b[0])
	}
	return
}

// array := length [elements]
func (d *Decoder) DecodeArray(t *cadence.ArrayType) (array cadence.Array, err error) {
	l, err := d.DecodeLength()
	if err != nil {
		return
	}

	array, err = cadence.NewMeteredArray(d.memoryGauge, l, func() ([]cadence.Value, error) {
		elements := make([]cadence.Value, 0, l)
		for i := 0; i < l; i++ {
			elementType, err := d.DecodeType()
			if err != nil {
				return nil, err
			}

			elementValue, err := d.DecodeValue(elementType)
			elements = append(elements, elementValue)
		}

		return elements, nil
	})

	array.WithType(*t)

	return
}

//
// Types
//

func (d *Decoder) DecodeType() (t cadence.Type, err error) {
	simpleType, err := d.DecodeSimpleType()

	switch simpleType {
	case EncodedTypeVoid:
		t = cadence.NewMeteredVoidType(d.memoryGauge)
	case EncodedTypeOptional:
		t, err = d.DecodeOptionalType()
	case EncodedTypeBool:
		t = cadence.NewMeteredVoidType(d.memoryGauge)
	case EncodedTypeVariableSizeArray:
		t, err = d.DecodeVariableSizedArrayType()
	case EncodedTypeConstantSizeArray:
		t, err = d.DecodeConstantSizedArrayType()
	}
	return
}

func (d *Decoder) DecodeSimpleType() (t EncodedType, err error) {
	b, err := d.read(1)
	t = EncodedType(b[0])
	return
}

// optionalType := -simpleOptionalType- elementType
func (d *Decoder) DecodeOptionalType() (t cadence.OptionalType, err error) {
	elementType, err := d.DecodeType()
	if err != nil {
		return
	}

	t = cadence.NewMeteredOptionalType(d.memoryGauge, elementType)
	return
}

// varArrayType := -simpleVarArrayType- elementType
func (d *Decoder) DecodeVariableSizedArrayType() (t cadence.VariableSizedArrayType, err error) {
	elementType, err := d.DecodeType()
	if err != nil {
		return
	}
	t = cadence.NewMeteredVariableSizedArrayType(d.memoryGauge, elementType)
	return
}

// conArrayType := -simpleConArrayType- elementType length
func (d *Decoder) DecodeConstantSizedArrayType() (t cadence.ConstantSizedArrayType, err error) {
	elementType, err := d.DecodeType()
	if err != nil {
		return
	}

	size, err := d.DecodeLength()
	if err != nil {
		return
	}

	t = cadence.NewMeteredConstantSizedArrayType(d.memoryGauge, uint(size), elementType)
	return
}

//
// Other
//

func (d *Decoder) DecodeLength() (l int, err error) {
	b, err := d.read(4)
	if err != nil {
		return
	}

	asUint32 := binary.LittleEndian.Uint32(b)
	l = int(asUint32)

	return
}

func (d *Decoder) read(howManyBytes int) (b []byte, err error) {
	b = make([]byte, howManyBytes)
	_, err = d.r.Read(b)
	return
}

//
// Sema
//

// A SemaDecoder decodes custom-encoded representations of Cadence values.
type SemaDecoder struct {
	r           io.Reader
	memoryGauge common.MemoryGauge
}

// Decode returns a Cadence value decoded from its custom-encoded representation.
//
// This function returns an error if the bytes represent a custom encoding that
// is malformed, does not conform to the custom Cadence specification, or contains
// an unknown composite type.
func DecodeSema(gauge common.MemoryGauge, b []byte) (sema.Type, error) {
	r := bytes.NewReader(b)
	dec := NewSemaDecoder(gauge, r)

	v, err := dec.Decode()
	if err != nil {
		return nil, err
	}

	return v, nil
}

// NewSemaDecoder initializes a SemaDecoder that will decode custom-encoded bytes from the
// given io.Reader.
func NewSemaDecoder(memoryGauge common.MemoryGauge, r io.Reader) *SemaDecoder {
	return &SemaDecoder{
		r:           r,
		memoryGauge: memoryGauge,
	}
}

// Decode reads custom-encoded bytes from the io.Reader and decodes them to a
// Sema type. There is no assumption about the top-level Sema type so the first
// byte must specify the top-level type. Usually this will be a CompositeType.
//
// This function returns an error if the bytes represent a custom encoding that
// is malformed, does not conform to the custom specification, or contains
// an unknown composite type.
func (d *SemaDecoder) Decode() (t sema.Type, err error) {
	// capture panics that occur during decoding
	defer func() {
		if r := recover(); r != nil {
			panicErr, isError := r.(error)
			if !isError {
				panic(r)
			}

			err = fmt.Errorf("failed to decode value: %w", panicErr)
		}
	}()

	return d.DecodeType()
}

func (d *SemaDecoder) DecodeType() (t sema.Type, err error) {
	typeIdentifier, err := d.DecodeTypeIdentifier()
	if err != nil {
		return
	}

	switch typeIdentifier {
	case EncodedSemaSimpleType:
		return d.DecodeSimpleType()
	case EncodedSemaCompositeType:
		return d.DecodeCompositeType()
	case EncodedSemaOptionalType:
		return d.DecodeOptionalType()
	case EncodedSemaGenericType:
		return d.DecodeGenericType()
	case EncodedSemaAddressType:
		t = &sema.AddressType{}
		return
	case EncodedSemaNumericType:
		return d.DecodeNumericType()
	case EncodedSemaFixedPointNumericType:
		return d.DecodeFixedPointNumericType()
	case EncodedSemaVariableSizedType:
		return d.DecodeVariableSizedType()
	case EncodedSemaConstantSizedType:
		return d.DecodeConstantSizedType()
	case EncodedSemaFunctionType:
		return d.DecodeFunctionType()
	case EncodedSemaDictionaryType:
		return d.DecodeDictionaryType()
	case EncodedSemaReferenceType:
		return d.DecodeReferenceType()
	case EncodedSemaTransactionType:
		return d.DecodeTransactionType()
	case EncodedSemaRestrictedType:
		return d.DecodeRestrictedType()
	case EncodedSemaCapabilityType:
		return d.DecodeCapabilityType()
	default:
		err = fmt.Errorf("unknown type identifier: %d", typeIdentifier)
	}

	return
}

func (d *SemaDecoder) DecodeCapabilityType() (ct *sema.CapabilityType, err error) {
	t, err := d.DecodeType()
	if err != nil {
		return
	}

	ct = &sema.CapabilityType{BorrowType: t}
	return
}

func (d *SemaDecoder) DecodeRestrictedType() (rt *sema.RestrictedType, err error) {
	t, err := d.DecodeType()
	if err != nil {
		return
	}

	restrictions, err := DecodeArray(d, d.DecodeInterfaceType)
	if err != nil {
		return
	}

	rt = &sema.RestrictedType{
		Type:         t,
		Restrictions: restrictions,
	}
	return
}

func (d *SemaDecoder) DecodeTransactionType() (tx *sema.TransactionType, err error) {
	members, err := d.DecodeStringMemberOrderedMap()
	if err != nil {
		return
	}

	fields, err := DecodeArray(d, d.DecodeString)
	if err != nil {
		return
	}

	prepareParameters, err := DecodeArray(d, d.DecodeParameter)
	if err != nil {
		return
	}

	parameters, err := DecodeArray(d, d.DecodeParameter)
	if err != nil {
		return
	}

	tx = &sema.TransactionType{
		Members:           members,
		Fields:            fields,
		PrepareParameters: prepareParameters,
		Parameters:        parameters,
	}
	return
}

func (d *SemaDecoder) DecodeReferenceType() (ref *sema.ReferenceType, err error) {
	authorized, err := d.DecodeBool()
	if err != nil {
		return
	}

	t, err := d.DecodeType()
	if err != nil {
		return
	}

	ref = &sema.ReferenceType{
		Authorized: authorized,
		Type:       t,
	}
	return
}

func (d *SemaDecoder) DecodeDictionaryType() (dict *sema.DictionaryType, err error) {
	keyType, err := d.DecodeType()
	if err != nil {
		return
	}

	valueType, err := d.DecodeType()
	if err != nil {
		return
	}

	dict = &sema.DictionaryType{
		KeyType:   keyType,
		ValueType: valueType,
	}
	return
}

func (d *SemaDecoder) DecodeFunctionType() (ft *sema.FunctionType, err error) {
	isConstructor, err := d.DecodeBool()
	if err != nil {
		return
	}

	typeParameters, err := DecodeArray(d, d.DecodeTypeParameter)
	if err != nil {
		return
	}

	parameters, err := DecodeArray(d, d.DecodeParameter)
	if err != nil {
		return
	}

	returnTypeAnnotation, err := d.DecodeTypeAnnotation()
	if err != nil {
		return
	}

	requiredArgmentCountInt64, err := d.DecodeInt64()
	if err != nil {
		return
	}
	requiredArgmentCount := int(requiredArgmentCountInt64)

	// TODO is ArgumentExpressionCheck needed?

	members, err := d.DecodeStringMemberOrderedMap()
	if err != nil {
		return
	}

	ft = &sema.FunctionType{
		IsConstructor:            isConstructor,
		TypeParameters:           typeParameters,
		Parameters:               parameters,
		ReturnTypeAnnotation:     returnTypeAnnotation,
		RequiredArgumentCount:    &requiredArgmentCount,
		ArgumentExpressionsCheck: nil,
		Members:                  members,
	}
	return
}

func (d *SemaDecoder) DecodeVariableSizedType() (a *sema.VariableSizedType, err error) {
	t, err := d.DecodeType()
	if err != nil {
		return
	}

	a = &sema.VariableSizedType{Type: t}
	return
}

func (d *SemaDecoder) DecodeConstantSizedType() (a *sema.ConstantSizedType, err error) {
	t, err := d.DecodeType()
	if err != nil {
		return
	}

	size, err := d.DecodeInt64()
	if err != nil {
		return
	}

	a = &sema.ConstantSizedType{
		Type: t,
		Size: size,
	}
	return
}

func (d *SemaDecoder) DecodeNumericType() (t *sema.NumericType, err error) {
	b, err := d.read(1)
	if err != nil {
		return
	}

	switch EncodedSemaNumericSubType(b[0]) {
	case EncodedSemaNumericSubTypeNumberType:
		t = sema.NumberType
	case EncodedSemaNumericSubTypeSignedNumberType:
		t = sema.SignedNumberType
	case EncodedSemaNumericSubTypeIntegerType:
		t = sema.IntegerType
	case EncodedSemaNumericSubTypeIntType:
		t = sema.IntType
	case EncodedSemaNumericSubTypeInt8Type:
		t = sema.Int8Type
	case EncodedSemaNumericSubTypeInt16Type:
		t = sema.Int16Type
	case EncodedSemaNumericSubTypeInt32Type:
		t = sema.Int32Type
	case EncodedSemaNumericSubTypeInt64Type:
		t = sema.Int64Type
	case EncodedSemaNumericSubTypeInt128Type:
		t = sema.Int128Type
	case EncodedSemaNumericSubTypeInt256Type:
		t = sema.Int256Type
	case EncodedSemaNumericSubTypeUIntType:
		t = sema.IntType
	case EncodedSemaNumericSubTypeUInt8Type:
		t = sema.Int8Type
	case EncodedSemaNumericSubTypeUInt16Type:
		t = sema.Int16Type
	case EncodedSemaNumericSubTypeUInt32Type:
		t = sema.Int32Type
	case EncodedSemaNumericSubTypeUInt64Type:
		t = sema.Int64Type
	case EncodedSemaNumericSubTypeUInt128Type:
		t = sema.Int128Type
	case EncodedSemaNumericSubTypeUInt256Type:
		t = sema.Int256Type
	case EncodedSemaNumericSubTypeWord8Type:
		t = sema.Word8Type
	case EncodedSemaNumericSubTypeWord16Type:
		t = sema.Word16Type
	case EncodedSemaNumericSubTypeWord32Type:
		t = sema.Word32Type
	case EncodedSemaNumericSubTypeWord64Type:
		t = sema.Word64Type
	case EncodedSemaNumericSubTypeFixedPointType:
		t = sema.FixedPointType
	case EncodedSemaNumericSubTypeSignedFixedPointType:
		t = sema.SignedFixedPointType
	default:
		err = fmt.Errorf("unknown numeric type: %d", b[0])
	}

	return
}

func (d *SemaDecoder) DecodeFixedPointNumericType() (t *sema.FixedPointNumericType, err error) {
	b, err := d.read(1)
	if err != nil {
		return
	}

	switch EncodedSemaFixedPointNumericSubType(b[0]) {
	case EncodedSemaFixedPointNumericSubTypeFix64Type:
		t = sema.Fix64Type
	case EncodedSemaFixedPointNumericSubTypeUFix64Type:
		t = sema.UFix64Type
	default:
		err = fmt.Errorf("unknown fixed point numeric type: %d", b[0])
	}

	return
}

func (d *SemaDecoder) DecodeIsNotNil() (isNotNil bool, err error) {
	return d.DecodeBool()
}

func (d *SemaDecoder) DecodeGenericType() (t *sema.GenericType, err error) {
	tp, err := d.DecodeTypeParameter()
	if err != nil {
		return
	}

	t = &sema.GenericType{TypeParameter: tp}
	return
}

func (d *SemaDecoder) DecodeOptionalType() (opt *sema.OptionalType, err error) {
	t, err := d.DecodeType()
	if err != nil {
		return
	}
	opt = &sema.OptionalType{Type: t}
	return
}

func (d *SemaDecoder) DecodeTypeIdentifier() (id EncodedSema, err error) {
	b, err := d.read(1)
	if err != nil {
		return
	}

	id = EncodedSema(b[0])
	return
}

func (d *SemaDecoder) DecodeSimpleType() (t *sema.SimpleType, err error) {
	b, err := d.read(1)
	if err != nil {
		return
	}

	switch EncodedSemaSimpleSubType(b[0]) {
	case EncodedSemaSimpleSubTypeAnyType:
		t = sema.AnyType
	case EncodedSemaSimpleSubTypeAnyResourceType:
		t = sema.AnyResourceType
	case EncodedSemaSimpleSubTypeAnyStructType:
		t = sema.AnyStructType
	case EncodedSemaSimpleSubTypeBlockType:
		t = sema.BlockType
	case EncodedSemaSimpleSubTypeBoolType:
		t = sema.BoolType
	case EncodedSemaSimpleSubTypeCharacterType:
		t = sema.CharacterType
	case EncodedSemaSimpleSubTypeDeployedContractType:
		t = sema.DeployedContractType
	case EncodedSemaSimpleSubTypeInvalidType:
		t = sema.InvalidType
	case EncodedSemaSimpleSubTypeMetaType:
		t = sema.MetaType
	case EncodedSemaSimpleSubTypeNeverType:
		t = sema.NeverType
	case EncodedSemaSimpleSubTypePathType:
		t = sema.PathType
	case EncodedSemaSimpleSubTypeStoragePathType:
		t = sema.StoragePathType
	case EncodedSemaSimpleSubTypeCapabilityPathType:
		t = sema.CapabilityPathType
	case EncodedSemaSimpleSubTypePublicPathType:
		t = sema.PublicPathType
	case EncodedSemaSimpleSubTypePrivatePathType:
		t = sema.PrivatePathType
	case EncodedSemaSimpleSubTypeStorableType:
		t = sema.StorableType
	case EncodedSemaSimpleSubTypeStringType:
		t = sema.StringType
	case EncodedSemaSimpleSubTypeVoidType:
		t = sema.VoidType
	default:
		err = fmt.Errorf("unknown simple subtype: %d", b[0])
	}

	return
}

func (d *SemaDecoder) DecodeCompositeType() (t *sema.CompositeType, err error) {
	location, err := d.DecodeLocation()
	if err != nil {
		return
	}

	identifier, err := d.DecodeString()
	if err != nil {
		return
	}

	kind, err := d.DecodeUInt64()
	if err != nil {
		return
	}

	explicitInterfaceConformances, err := DecodeArray(d, d.DecodeInterfaceType)
	if err != nil {
		return
	}

	implicitTypeRequirementConformances, err := DecodeArray(d, d.DecodeCompositeType)
	if err != nil {
		return
	}

	members, err := d.DecodeStringMemberOrderedMap()
	if err != nil {
		return
	}

	fields, err := DecodeArray(d, d.DecodeString)
	if err != nil {
		return
	}

	constructorParameters, err := DecodeArray(d, d.DecodeParameter)
	if err != nil {
		return
	}

	containerType, err := d.DecodeType()
	if err != nil {
		return
	}

	enumRawType, err := d.DecodeType()
	if err != nil {
		return
	}

	importableWithoutLocation, err := d.DecodeBool()
	if err != nil {
		return
	}

	t = &sema.CompositeType{
		Location:                            location,
		Identifier:                          identifier,
		Kind:                                common.CompositeKind(kind),
		ExplicitInterfaceConformances:       explicitInterfaceConformances,
		ImplicitTypeRequirementConformances: implicitTypeRequirementConformances,
		Members:                             members,
		Fields:                              fields,
		ConstructorParameters:               constructorParameters,
		EnumRawType:                         enumRawType,
		ImportableWithoutLocation:           importableWithoutLocation,
	}
	t.SetContainerType(containerType)
	return
}

func (d *SemaDecoder) DecodeInterfaceType() (t *sema.InterfaceType, err error) {
	// TODO

	t = &sema.InterfaceType{
		Location:              nil,
		Identifier:            "",
		CompositeKind:         0,
		Members:               nil,
		Fields:                nil,
		InitializerParameters: nil,
	}
	return
}

func (d *SemaDecoder) DecodeTypeParameter() (p *sema.TypeParameter, err error) {
	name, err := d.DecodeString()
	if err != nil {
		return
	}

	bound, err := d.DecodeType()
	if err != nil {
		return
	}

	optional, err := d.DecodeBool()
	if err != nil {
		return
	}

	p = &sema.TypeParameter{
		Name:      name,
		TypeBound: bound,
		Optional:  optional,
	}
	return
}

func (d *SemaDecoder) DecodeParameter() (parameter *sema.Parameter, err error) {
	label, err := d.DecodeString()
	if err != nil {
		return
	}

	id, err := d.DecodeString()
	if err != nil {
		return
	}

	anno, err := d.DecodeTypeAnnotation()
	if err != nil {
		return
	}

	parameter = &sema.Parameter{
		Label:          label,
		Identifier:     id,
		TypeAnnotation: anno,
	}

	return
}

func (d *SemaDecoder) DecodeStringMemberOrderedMap() (om *sema.StringMemberOrderedMap, err error) {
	length, err := d.DecodeLength()
	if err != nil {
		return
	}

	om = sema.NewStringMemberOrderedMap()

	for i := 0; i < length; i++ {
		var key string
		key, err = d.DecodeString()
		if err != nil {
			return
		}

		var member *sema.Member
		member, err = d.DecodeMember()
		if err != nil {
			return
		}

		om.Set(key, member)
	}

	return
}

func (d *SemaDecoder) DecodeMember() (member *sema.Member, err error) {
	containerType, err := d.DecodeType()
	if err != nil {
		return
	}

	access, err := d.DecodeUInt64()
	if err != nil {
		return
	}

	identifier, err := d.DecodeAstIdentifier()
	if err != nil {
		return
	}

	typeAnnotation, err := d.DecodeTypeAnnotation()
	if err != nil {
		return
	}

	declarationKind, err := d.DecodeUInt64()
	if err != nil {
		return
	}

	variableKind, err := d.DecodeUInt64()
	if err != nil {
		return
	}

	argumentLabels, err := DecodeArray(d, d.DecodeString)
	if err != nil {
		return
	}

	predeclared, err := d.DecodeBool()
	if err != nil {
		return
	}

	docString, err := d.DecodeString()
	if err != nil {
		return
	}

	member = &sema.Member{
		ContainerType:         containerType,
		Access:                ast.Access(access),
		Identifier:            identifier,
		TypeAnnotation:        typeAnnotation,
		DeclarationKind:       common.DeclarationKind(declarationKind),
		VariableKind:          ast.VariableKind(variableKind),
		ArgumentLabels:        argumentLabels,
		Predeclared:           predeclared,
		IgnoreInSerialization: false, // wouldn't be encoded in the first place if true
		DocString:             docString,
	}
	return
}

func (d *SemaDecoder) DecodeAstIdentifier() (id ast.Identifier, err error) {
	identifier, err := d.DecodeString()
	if err != nil {
		return
	}

	position, err := d.DecodeAstPosition()
	if err != nil {
		return
	}

	id = ast.Identifier{
		Identifier: identifier,
		Pos:        position,
	}
	return
}

func (d *SemaDecoder) DecodeAstPosition() (pos ast.Position, err error) {
	offset, err := d.DecodeInt64()
	if err != nil {
		return
	}

	line, err := d.DecodeInt64()
	if err != nil {
		return
	}

	column, err := d.DecodeInt64()
	if err != nil {
		return
	}

	pos = ast.Position{
		Offset: int(offset),
		Line:   int(line),
		Column: int(column),
	}
	return
}

func (d *SemaDecoder) DecodeTypeAnnotation() (anno *sema.TypeAnnotation, err error) {
	isResource, err := d.DecodeBool()
	if err != nil {
		return
	}

	t, err := d.DecodeType()
	if err != nil {
		return
	}

	anno = &sema.TypeAnnotation{
		IsResource: isResource,
		Type:       t,
	}
	return
}

func (d *SemaDecoder) DecodeLocation() (location common.Location, err error) {
	prefix, err := d.DecodeLocationPrefix()

	switch prefix {
	case common.AddressLocationPrefix:
		return d.DecodeAddressLocation()
		// TODO more locations
	default:
		err = fmt.Errorf("unknown location prefix: %s", prefix)
	}
	return
}

func (d *SemaDecoder) DecodeLocationPrefix() (prefix string, err error) {
	b, err := d.read(1)
	prefix = string(b)
	return
}

func (d *SemaDecoder) DecodeAddressLocation() (location common.AddressLocation, err error) {
	address, err := d.DecodeAddress()
	if err != nil {
		return
	}

	name, err := d.DecodeString()
	if err != nil {
		return
	}

	location = common.NewAddressLocation(d.memoryGauge, address, name)

	return
}

func (d *SemaDecoder) DecodeAddress() (address common.Address, err error) {
	byteArray, err := d.read(common.AddressLength)
	if err != nil {
		return
	}

	for i, b := range byteArray {
		address[i] = b
	}

	return
}

func (d *SemaDecoder) DecodeString() (s string, err error) {
	b, err := d.DecodeBytes()
	if err != nil {
		return
	}

	s = string(b)
	return
}

func (d *SemaDecoder) DecodeBytes() (bytes []byte, err error) {
	length, err := d.DecodeLength()
	if err != nil {
		return
	}

	return d.read(length)
}

func (d *SemaDecoder) DecodeLength() (length int, err error) {
	b, err := d.read(4)
	if err != nil {
		return
	}

	asUint32 := binary.LittleEndian.Uint32(b)
	length = int(asUint32)
	return
}

func (d *SemaDecoder) DecodeBool() (boolean bool, err error) {
	b, err := d.read(1)
	if err != nil {
		return
	}

	switch b[0] {
	case 0:
		boolean = false
	case 1:
		boolean = true
	default:
		err = fmt.Errorf("invalid boolean value: %d", b[0])
	}

	return
}

func (d *SemaDecoder) DecodeUInt64() (u uint64, err error) {
	err = binary.Read(d.r, binary.LittleEndian, &u)
	return
}

func (d *SemaDecoder) DecodeInt64() (i int64, err error) {
	err = binary.Read(d.r, binary.LittleEndian, &i)
	return
}

func (d *SemaDecoder) read(howManyBytes int) (b []byte, err error) {
	b = make([]byte, howManyBytes)
	_, err = d.r.Read(b)
	return
}

func DecodeArray[T any](d *SemaDecoder, decodeFn func() (T, error)) (arr []T, err error) {
	length, err := d.DecodeLength()
	if err != nil {
		return
	}

	arr = make([]T, length)
	for i := 0; i < length; i++ {
		var element T
		element, err = decodeFn()
		if err != nil {
			return
		}

		arr[i] = element
	}

	return
}
