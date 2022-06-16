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
	"github.com/onflow/cadence"
	"github.com/onflow/cadence/runtime/ast"
	"github.com/onflow/cadence/runtime/common"
	"github.com/onflow/cadence/runtime/sema"
	"io"
	"math/big"
	goRuntime "runtime"
)

// An Encoder converts Cadence values into custom-encoded bytes.
type Encoder struct {
	w          io.Writer
}

// Encode returns the custom-encoded representation of the given value.
//
// This function returns an error if the Cadence value cannot be represented in the custom format.
func Encode(value cadence.Value) ([]byte, error) {
	var w bytes.Buffer
	enc := NewEncoder(&w)

	err := enc.Encode(value)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// MustEncode returns the custom-encoded representation of the given value, or panics
// if the value cannot be represented in the custom format.
func MustEncode(value cadence.Value) []byte {
	b, err := Encode(value)
	if err != nil {
		panic(err)
	}
	return b
}

// NewEncoder initializes an Encoder that will write custom-encoded bytes to the
// given io.Writer.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// Encode writes the custom-encoded representation of the given value to this
// encoder's io.Writer.
//
// This function returns an error if the given value's type is not supported
// by this encoder.
func (e *Encoder) Encode(value cadence.Value) (err error) {
	// capture panics that occur during struct preparation
	defer func() {
		if r := recover(); r != nil {
			// don't recover Go errors
			goErr, ok := r.(goRuntime.Error)
			if ok {
				panic(goErr)
			}

			panicErr, isError := r.(error)
			if !isError {
				panic(r)
			}

			err = fmt.Errorf("failed to encode value: %w", panicErr)
		}
	}()

	return e.EncodeValue(value)

	// 1. find the value's type
	// 2. call the custom encoder for that type
	// this custom encoder calls specific encoders for known types of composite elements
	// it calls a general sub function fo
}

//
// Values
//

// EncodeValue encodes any supported cadence.Value.
func (e *Encoder) EncodeValue(value cadence.Value) (err error) {
	switch v := value.(type) {
	case cadence.Void:
		return e.EncodeVoid()
	case cadence.Optional:
		return e.EncodeOptional(v)
	case cadence.Array:
		return e.EncodeArray(v)
	case cadence.Bool:
		return e.EncodeBool(v)
	}
	return
}

// void := 0
func (e *Encoder) EncodeVoid() (err error) {
	_, err = e.w.Write([]byte{0}) // TODO when writing Decoder, figure out if void even needs a value
	return
}

// optional := typedValue
func (e *Encoder) EncodeOptional(value cadence.Optional) (err error) {
	err = e.EncodeType(value.Value.Type())
	if err != nil { return }

	return e.EncodeValue(value.Value)
}

// bool := false | true
// false := 0
// true := 1
func (e *Encoder) EncodeBool(value cadence.Bool) (err error) {
	b := []byte{0}
	if value {
		b[0] = 1
	}

	_, err = e.w.Write(b)
	return
}

// array := length [elements]
func (e *Encoder) EncodeArray(value cadence.Array) (err error) {
	err = e.EncodeLength(len(value.Values))
	if err != nil { return }

	for _, element := range value.Values {
		err = e.EncodeType(element.Type())
		if err != nil { return err }

		err = e.EncodeValue(element)
		if err != nil { return err }
	}

	return
}

//
// Types
//

// TODO do each of the type encoders need to include their type?
//      or can they sometimes have a known type?
func (e *Encoder) EncodeType(t cadence.Type) (err error) {
	switch actualType := t.(type) {
	case cadence.VoidType:
		return e.EncodeSimpleType(EncodedTypeVoid)
	case cadence.OptionalType:
		return e.EncodeOptionalType(actualType)
	case cadence.BoolType:
		return e.EncodeSimpleType(EncodedTypeBool)
	case cadence.VariableSizedArrayType:
		return e.EncodeVariableSizedArrayType(actualType)
	case cadence.ConstantSizedArrayType:
		return e.EncodeConstantSizedArrayType(actualType)
	}
	return
}

// simpleType := byte
func (e *Encoder) EncodeSimpleType(t EncodedType) (err error) {
	_, err = e.w.Write([]byte{byte(t)})
	return
}

// optionalType := simpleOptionalType elementType
func (e *Encoder) EncodeOptionalType(t cadence.OptionalType) (err error) {
	err = e.EncodeSimpleType(EncodedTypeOptional)
	if err != nil { return }

	return e.EncodeType(t.Type)
}

// EncodeVariableSizedArrayType encoded a variable-sized array into the custom format.
// It's at least 2 bytes:
// 1. The simple type `EncodedTypeVariableSizeArray`.
// 2. Its element type, which is one or more bytes.
// varArrayType := simpleVarArrayType elementType
func (e *Encoder) EncodeVariableSizedArrayType(t cadence.VariableSizedArrayType) (err error) {
	err = e.EncodeSimpleType(EncodedTypeVariableSizeArray)
	if err != nil { return }

	return e.EncodeType(t.ElementType)
}

// EncodeVariableSizedArrayType encoded a variable-sized array into the custom format.
// It's at least 2 bytes:
// 1. The simple type `EncodedTypeVariableSizeArray`.
// 2. Its element type, which is one or more bytes.
// conArrayType := simpleConArrayType elementType length
func (e *Encoder) EncodeConstantSizedArrayType(t cadence.ConstantSizedArrayType) (err error) {
	err = e.EncodeSimpleType(EncodedTypeConstantSizeArray)
	if err != nil { return }

	err = e.EncodeType(t.ElementType)
	if err != nil { return }

	return e.EncodeLength(int(t.Size))
}

//
// Other
//

// EncodeLength encodes a non-negative length as a uint32.
// It uses 4 bytes.
func (e *Encoder) EncodeLength(length int) (err error) {
	if length < 0 { // TODO is this safety check useful?
		return fmt.Errorf("Cannot encode length below zero: %d", length)
	}

	// TODO is type conversion safe here?
	// TODO could type conversion be done cheaper since length is for sure positive?
	l := uint32(length)
	blob := make([]byte, 4)
	binary.LittleEndian.PutUint32(blob, l)

	_, err = e.w.Write(blob)

	return
}

type EncodedType byte

const (
	EncodedTypeUnknown EncodedType = iota
	EncodedTypeVoid
	EncodedTypeOptional
	EncodedTypeBool
	EncodedTypeVariableSizeArray
	EncodedTypeConstantSizeArray
)

//
// Sema Types
//

// A SemaEncoder converts Sema types into custom-encoded bytes.
type SemaEncoder struct {
	w          io.Writer
}

// EncodeSema returns the custom-encoded representation of the given sema type.
//
// This function returns an error if the Cadence value cannot be represented in the custom format.
func EncodeSema(t sema.Type) ([]byte, error) {
	var w bytes.Buffer
	enc := NewSemaEncoder(&w)

	err := enc.Encode(t)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// MustEncodeSema returns the custom-encoded representation of the given sema type, or panics
// if the sema type cannot be represented in the custom format.
func MustEncodeSema(value cadence.Value) []byte {
	b, err := Encode(value)
	if err != nil {
		panic(err)
	}
	return b
}

// NewSemaEncoder initializes a SemaEncoder that will write custom-encoded bytes to the
// given io.Writer.
func NewSemaEncoder(w io.Writer) *SemaEncoder {
	return &SemaEncoder{w: w}
}

// Encode writes the custom-encoded representation of the given sema type to this
// encoder's io.Writer.
//
// This function returns an error if the given sema type is not supported
// by this encoder.
func (e *SemaEncoder) Encode(t sema.Type) (err error) {
	// capture panics that occur during struct preparation
	defer func() {
		if r := recover(); r != nil {
			// don't recover Go errors
			goErr, ok := r.(goRuntime.Error)
			if ok {
				panic(goErr)
			}

			panicErr, isError := r.(error)
			if !isError {
				panic(r)
			}

			err = fmt.Errorf("failed to encode value: %w", panicErr)
		}
	}()

	return e.EncodeType(t)
}

// EncodeType encodes any supported sema.Type.
func (e *SemaEncoder) EncodeType(t sema.Type) (err error) {

	err = e.EncodeTypeIdentifier(t)
	if err != nil { return }

	switch concreteType := t.(type) {
	case *sema.SimpleType:
		return e.EncodeSimpleType(concreteType)
	case *sema.CompositeType:
		return e.EncodeCompositeType(concreteType)
	//case sema.ValueIndexableType:
	//	panic("TODO")
	//case sema.ContainedType:
	//	panic("TODO")
	//case sema.ContainerType:
	//	panic("TODO")
	//case sema.CompositeKindedType:
	//	panic("TODO")
	//case sema.LocatedType:
	//	panic("TODO")
	//case sema.ParameterizedType:
	//	panic("TODO")
	case *sema.OptionalType:
		return e.EncodeOptionalType(concreteType)
	case *sema.GenericType:
		return e.EncodeGenericType(concreteType)
	case sema.IntegerRangedType:
		return e.EncodeIntegerRangedType(concreteType)
	case sema.FractionalRangedType:
		return e.EncodeFractionalRangedType(concreteType)
	//case sema.SaturatingArithmeticType:
	//	panic("TODO")
	case sema.ArrayType:
		return e.EncodeArrayType(concreteType)
	case *sema.FunctionType:
		return e.EncodeFunctionType(concreteType)
	case *sema.DictionaryType:
		return e.EncodeDictionaryType(concreteType)
	case *sema.ReferenceType:
		return e.EncodeReferenceType(concreteType)
	case *sema.AddressType:
		return // type is an empty struct
	case *sema.TransactionType:
		return e.EncodeTransactionType(concreteType)
	case *sema.RestrictedType:
		return e.EncodeRestrictedType(concreteType)
	case *sema.CapabilityType:
		return e.EncodeCapabilityType(concreteType)
	default:
		return fmt.Errorf("unexpected type: %s", concreteType)
	}
}

func (e *SemaEncoder) EncodeSimpleType(t *sema.SimpleType) (err error) {
	err = e.EncodeString(t.Name)
	if err != nil { return }

	err = e.EncodeString(t.QualifiedString())
	if err != nil { return }

	err = e.EncodeString(string(t.TypeID))
	if err != nil { return }

	err = e.EncodeTypeTag(t.Tag())
	if err != nil { return }

	err = e.EncodeBool(t.IsInvalid)
	if err != nil { return }

	err = e.EncodeBool(t.IsResource)
	if err != nil { return }

	err = e.EncodeBool(t.Storable)
	if err != nil { return }

	err = e.EncodeBool(t.Equatable)
	if err != nil { return }

	err = e.EncodeBool(t.ExternallyReturnable)
	if err != nil { return }

	err = e.EncodeBool(t.Importable)
	if err != nil { return }

	// TODO how to handle IsSuperTypeOf?
	//      should we encode each simple type as an enum?
	//      then the decoder would find the instantiated simple types

	// TODO Members

	err = e.EncodeStringTypeOrderedMap(t.NestedTypes)
	if err != nil { return }

	return e.EncodeValueIndexingInfo(t.ValueIndexingInfo)
}

func (e *SemaEncoder) EncodeValueIndexingInfo(info sema.ValueIndexingInfo) (err error) {
	err = e.EncodeBool(info.IsValueIndexableType)
	if err != nil { return }

	err = e.EncodeBool(info.AllowsValueIndexingAssignment)
	if err != nil { return }

	// TODO ElementType? it's a function, so...

	return e.EncodeNumericType(info.IndexingType)
}

func (e *SemaEncoder) EncodeArrayType(t sema.ArrayType) (err error) {
	switch concreteType := t.(type) {
	case *sema.VariableSizedType:
		return e.EncodeVariableSizedType(concreteType)
	case *sema.ConstantSizedType:
		return e.EncodeConstantSizedType(concreteType)
	default:
		return fmt.Errorf("Unexpected array type: %s", concreteType)
	}
}

func (e *SemaEncoder) EncodeFunctionType(t *sema.FunctionType) (err error) {
	err = e.EncodeBool(t.IsConstructor)
	if err != nil { return }

	err = e.EncodeLength(len(t.TypeParameters))
	if err != nil { return }
	for _, p := range t.TypeParameters {
		err = e.EncodeTypeParameter(p)
		if err != nil { return }
	}

	err = e.EncodeLength(len(t.Parameters))
	if err != nil { return }
	for _, p := range t.Parameters {
		err = e.EncodeParameter(p)
		if err != nil { return }
	}

	err = e.EncodeTypeAnnotation(t.ReturnTypeAnnotation)
	if err != nil { return }

	err = e.EncodeInt64(int64(*t.RequiredArgumentCount))
	if err != nil { return }

	// TODO can ArgumentExpressionCheck by omitted?

	return e.EncodeStringMemberOrderedMap(t.Members)
}

func (e *SemaEncoder) EncodeDictionaryType(t *sema.DictionaryType) (err error) {
	err = e.EncodeType(t.KeyType)
	if err != nil { return }

	return e.EncodeType(t.ValueType)
}

func (e *SemaEncoder) EncodeReferenceType(t *sema.ReferenceType) (err error) {
	err = e.EncodeBool(t.Authorized)
	if err != nil { return }

	return e.EncodeType(t.Type)
}

func (e *SemaEncoder) EncodeTransactionType(t *sema.TransactionType) (err error) {
	err = e.EncodeStringMemberOrderedMap(t.Members)
	if err != nil { return }

	err = e.EncodeLength(len(t.Fields))
	if err != nil { return }
	for _, field := range t.Fields {
		err = e.EncodeString(field)
		if err != nil { return }
	}

	err = e.EncodeLength(len(t.PrepareParameters))
	if err != nil { return }
	for _, p := range t.PrepareParameters {
		err = e.EncodeParameter(p)
		if err != nil { return }
	}

	err = e.EncodeLength(len(t.Parameters))
	if err != nil { return }
	for _, p := range t.Parameters {
		err = e.EncodeParameter(p)
		if err != nil { return }
	}

	return
}

func (e *SemaEncoder) EncodeRestrictedType(t *sema.RestrictedType) (err error) {
	err = e.EncodeType(t.Type)
	if err != nil { return }

	err = e.EncodeLength(len(t.Restrictions))
	if err != nil { return }
	for _, inter := range t.Restrictions {
		err = e.EncodeInterfaceType(inter)
		if err != nil { return }
	}

	return
}

func (e *SemaEncoder) EncodeCapabilityType(t *sema.CapabilityType) (err error) {
	return e.EncodeType(t.BorrowType)
}

func (e *SemaEncoder) EncodeOptionalType(t *sema.OptionalType) (err error) {
	return e.EncodeType(t.Type)
}

func (e *SemaEncoder) EncodeVariableSizedType(t *sema.VariableSizedType) (err error) {
	return e.EncodeType(t.Type)
}

func (e *SemaEncoder) EncodeConstantSizedType(t *sema.ConstantSizedType) (err error) {
	err = e.EncodeType(t.Type)
	if err != nil { return }

	return e.EncodeInt64(t.Size)
}

func (e *SemaEncoder) EncodeGenericType(t *sema.GenericType) (err error) {
	return e.EncodeTypeParameter(t.TypeParameter)
}

func (e *SemaEncoder) EncodeIntegerRangedType(t sema.IntegerRangedType) (err error) {
	// TODO more types?
	// TODO encode more concrete types instead? like cadence's Int16
	switch concreteType := t.(type) {
	case *sema.NumericType:
		return e.EncodeNumericType(concreteType)
	default:
		return fmt.Errorf("Unexpected integer ranged type: %s", concreteType)
	}
}

func (e *SemaEncoder) EncodeNumericType(t *sema.NumericType) (err error) {
	err = e.EncodeIsNonNil(t)
	if err != nil || t == nil { return }

	// name -> string
	err = e.EncodeString(t.QualifiedString())
	if err != nil { return }

	err = e.EncodeTypeTag(t.Tag())
	if err != nil { return }

	err = e.EncodeBigInt(t.MinInt())
	if err != nil { return }

	err = e.EncodeBigInt(t.MaxInt())
	if err != nil { return }

	err = e.EncodeBool(t.SupportsSaturatingAdd())
	if err != nil { return }

	err = e.EncodeBool(t.SupportsSaturatingSubtract())
	if err != nil { return }

	err = e.EncodeBool(t.SupportsSaturatingMultiply())
	if err != nil { return }

	err = e.EncodeBool(t.SupportsSaturatingDivide())
	if err != nil { return }

	return e.EncodeBool(t.IsSuperType())
}

// EncodePresent indicates if the following value is nil or non-nil.
func (e *SemaEncoder) EncodeIsNonNil(thing any) (err error) {
	return e.EncodeBool(thing != nil)
}

func (e *SemaEncoder) EncodeFractionalRangedType(t sema.FractionalRangedType) (err error) {
	// TODO more types?
	// TODO encode more concrete types instead? like cadence's Fix64
	switch concreteType := t.(type) {
	case *sema.FixedPointNumericType:
		return e.EncodeFixedPointNumericType(concreteType)
	default:
		return fmt.Errorf("Unexpected fractional ranged type: %s", concreteType)
	}
}

func (e *SemaEncoder) EncodeFixedPointNumericType(t *sema.FixedPointNumericType) (err error) {
	// name -> string
	err = e.EncodeString(t.QualifiedString())
	if err != nil { return }

	err = e.EncodeTypeTag(t.Tag())
	if err != nil { return }

	err = e.EncodeUInt64(uint64(t.Scale()))
	if err != nil { return }

	err = e.EncodeBigInt(t.MinInt())
	if err != nil { return }

	err = e.EncodeBigInt(t.MaxInt())
	if err != nil { return }

	err = e.EncodeBool(t.SupportsSaturatingAdd())
	if err != nil { return }

	err = e.EncodeBool(t.SupportsSaturatingSubtract())
	if err != nil { return }

	err = e.EncodeBool(t.SupportsSaturatingMultiply())
	if err != nil { return }

	err = e.EncodeBool(t.SupportsSaturatingDivide())
	if err != nil { return }

	return e.EncodeBool(t.IsSuperType())
}

func (e *SemaEncoder) EncodeBigInt(bi *big.Int) (err error) {
	sign := bi.Sign()
	neg := sign == -1
	err = e.EncodeBool(neg)
	if err != nil { return }

	return e.EncodeBytes(bi.Bytes())
}

func (e *SemaEncoder) EncodeTypeTag(tag sema.TypeTag) (err error) {
	err = e.EncodeUInt64(tag.UpperMask())
	if err != nil { return }

	return e.EncodeUInt64(tag.LowerMask())
}

// TODO can I use TypeTag instead? runtime/sema/type_tags.go:32
type EncodedSema byte

const (
	EncodedSemaUnknown EncodedSema = iota
	EncodedSemaSimpleType
	EncodedSemaCompositeType
	EncodedSemaOptionalType
	EncodedSemaGenericType
	EncodedSemaNumericType
	EncodedSemaFixedPointNumericType
	EncodedSemaVariableSizedType
	EncodedSemaConstantSizedType
	EncodedSemaFunctionType
	EncodedSemaDictionaryType
	EncodedSemaReferenceType
	EncodedSemaAddressType
	EncodedSemaTransactionType
	EncodedSemaRestrictedType
	EncodedSemaCapabilityType
)

func (e *SemaEncoder) EncodeTypeIdentifier(t sema.Type) (err error) {
	id := EncodedSemaUnknown
	switch concreteType := t.(type) {
	case *sema.SimpleType:
		id = EncodedSemaSimpleType
	case *sema.CompositeType:
		id = EncodedSemaCompositeType
	case *sema.OptionalType:
		id = EncodedSemaOptionalType
	case *sema.GenericType:
		id = EncodedSemaGenericType
	case *sema.NumericType:
		id = EncodedSemaNumericType
	case *sema.FixedPointNumericType:
		id = EncodedSemaFixedPointNumericType
	case *sema.VariableSizedType:
		id = EncodedSemaVariableSizedType
	case *sema.ConstantSizedType:
		id = EncodedSemaConstantSizedType
	case *sema.FunctionType:
		id = EncodedSemaFunctionType
	case *sema.DictionaryType:
		id = EncodedSemaDictionaryType
	case *sema.ReferenceType:
		id = EncodedSemaReferenceType
	case *sema.AddressType:
		id = EncodedSemaAddressType
	case *sema.TransactionType:
		id = EncodedSemaTransactionType
	case *sema.RestrictedType:
		id = EncodedSemaRestrictedType
	case *sema.CapabilityType:
		id = EncodedSemaCapabilityType
	default:
		return fmt.Errorf("unexpected type: %s", concreteType)
	}

	return e.write([]byte{byte(id)})
}

// TODO are composite types encodable is CompositeType.IsStorable() is false?
// TODO if IsImportable is false then do we want to skip for execution state storage?
func (e *SemaEncoder) EncodeCompositeType(compositeType *sema.CompositeType) (err error) {
	// Location -> common.Location
	err = e.EncodeLocation(compositeType.Location)
	if err != nil { return }

	// Identifier -> string
	err = e.EncodeString(compositeType.Identifier)
	if err != nil { return }

	// Kind -> common.CompositeKind
	err = e.EncodeUInt64(uint64(compositeType.Kind))
	if err != nil { return }

	// ExplicitInterfaceConformances -> []*InterfaceType
	err = e.EncodeLength(len(compositeType.ExplicitInterfaceConformances))
	if err != nil { return }
	for _, interfaceType := range compositeType.ExplicitInterfaceConformances {
		err = e.EncodeInterfaceType(interfaceType)
		if err != nil { return }
	}

	// ImplicitTypeRequirementConformances -> []*CompositeType
	err = e.EncodeLength(len(compositeType.ImplicitTypeRequirementConformances))
	if err != nil { return }
	for _, conf := range compositeType.ImplicitTypeRequirementConformances {
		err = e.EncodeCompositeType(conf)
		if err != nil { return }
	}

	// Members -> *StringMemberOrderedMap
	err = e.EncodeStringMemberOrderedMap(compositeType.Members)
	if err != nil { return }

	// Fields -> []string
	err = e.EncodeLength(len(compositeType.Fields))
	if err != nil { return }
	for _, s := range compositeType.Fields {
		err = e.EncodeString(s)
		if err != nil { return }
	}

	// ConstructorParameters -> []*Parameter
	err = e.EncodeLength(len(compositeType.ConstructorParameters))
	if err != nil { return }
	for _, parameter := range compositeType.ConstructorParameters {
		err = e.EncodeParameter(parameter)
		if err != nil { return }
	}

	// nestedTypes -> *StringTypeOrderedMap
	err = e.EncodeStringTypeOrderedMap(compositeType.GetNestedTypes())
	if err != nil { return }

	// containerType -> Type
	err = e.EncodeType(compositeType.GetContainerType())
	if err != nil { return }

	// EnumRawType -> Type
	err = e.EncodeType(compositeType.EnumRawType)
	if err != nil { return }

	// TODO? hasComputedMembers    bool

	// ImportableWithoutLocation -> bool
	return e.EncodeBool(compositeType.ImportableWithoutLocation)
}


func (e *SemaEncoder) EncodeTypeParameter(p *sema.TypeParameter) (err error) {
	err = e.EncodeString(p.Name)
	if err != nil { return }

	err = e.EncodeType(p.TypeBound)
	if err != nil { return }

	return e.EncodeBool(p.Optional)
}

func (e *SemaEncoder) EncodeParameter(parameter *sema.Parameter) (err error) {
	err = e.EncodeString(parameter.Label)
	if err != nil { return }

	err = e.EncodeString(parameter.Identifier)
	if err != nil { return }

	return e.EncodeTypeAnnotation(parameter.TypeAnnotation)
}

func (e *SemaEncoder) EncodeStringMemberOrderedMap(om *sema.StringMemberOrderedMap) (err error) {
	if om == nil {
		return e.EncodeLength(0)
	}

	err = e.EncodeLength(om.Len())
	if err != nil { return }

	return om.ForeachWithError(func(key string, value *sema.Member) error {
		if value.IgnoreInSerialization {
			return nil
		}

		err := e.EncodeString(key)
		if err != nil { return err }

		return e.EncodeMember(value)
	})
}

func (e *SemaEncoder) EncodeStringTypeOrderedMap(om *sema.StringTypeOrderedMap) (err error) {
	if om == nil {
		return e.EncodeLength(0)
	}

	err = e.EncodeLength(om.Len())
	if err != nil { return }

	return om.ForeachWithError(func(key string, t sema.Type) error {
		err := e.EncodeString(key)
		if err != nil { return err }

		return e.EncodeType(t)
	})
}

func (e *SemaEncoder) EncodeMember(member *sema.Member) (err error) {
	err = e.EncodeType(member.ContainerType)
	if err != nil { return }

	err = e.EncodeUInt64(uint64(member.Access))
	if err != nil { return }

	err = e.EncodeAstIdentifier(member.Identifier)
	if err != nil { return }

	err = e.EncodeTypeAnnotation(member.TypeAnnotation)
	if err != nil { return }

	err = e.EncodeUInt64(uint64(member.DeclarationKind))
	if err != nil { return }

	err = e.EncodeUInt64(uint64(member.VariableKind))
	if err != nil { return }

	err = e.EncodeLength(len(member.ArgumentLabels))
	if err != nil { return }
	for _, s := range member.ArgumentLabels {
		err = e.EncodeString(s)
		if err != nil { return }
	}

	err = e.EncodeBool(member.Predeclared)
	if err != nil { return }

	return e.EncodeString(member.DocString)
}

func (e *SemaEncoder) EncodeTypeAnnotation(anno *sema.TypeAnnotation) (err error) {
	err = e.EncodeBool(anno.IsResource)
	if err != nil { return }

	return e.EncodeType(anno.Type)
}

func (e *SemaEncoder) EncodeAstIdentifier(id ast.Identifier) (err error) {
	err = e.EncodeString(id.Identifier)
	if err != nil { return }

	return e.EncodeAstPosition(id.Pos)
}

func (e *SemaEncoder) EncodeAstPosition(pos ast.Position) (err error) {
	err = e.EncodeInt64(int64(pos.Offset))
	if err != nil { return }

	err = e.EncodeInt64(int64(pos.Line))
	if err != nil { return }

	return e.EncodeInt64(int64(pos.Column))
}

func (e *SemaEncoder) EncodeInterfaceType(interfaceType *sema.InterfaceType) (err error) {
	err = e.EncodeLocation(interfaceType.Location)
	if err != nil { return }

	err = e.EncodeString(interfaceType.Identifier)
	if err != nil { return }

	err = e.EncodeUInt64(uint64(interfaceType.CompositeKind))
	if err != nil { return }

	err = e.EncodeStringMemberOrderedMap(interfaceType.Members)
	if err != nil { return }

	err = e.EncodeLength(len(interfaceType.Fields))
	if err != nil { return }
	for _, s := range interfaceType.Fields {
		err = e.EncodeString(s)
		if err != nil { return }
	}

	err = e.EncodeLength(len(interfaceType.InitializerParameters))
	if err != nil { return }
	for _, parameter := range interfaceType.InitializerParameters {
		err = e.EncodeParameter(parameter)
		if err != nil { return }
	}

	err = e.EncodeType(interfaceType.GetContainerType())
	if err != nil { return }

	return e.EncodeStringTypeOrderedMap(interfaceType.GetNestedTypes())
}

func (e *SemaEncoder) EncodeBool(boolean bool) (err error) {
	b := []byte{0}
	if boolean {
		b[0] = 1
	}
	return e.write(b)
}

// TODO use a more efficient encoder than `binary` (they say to in their top source comment)
func (e *SemaEncoder) EncodeUInt64(i uint64) (err error) {
	return binary.Write(e.w, binary.LittleEndian, i)
}

func (e *SemaEncoder) EncodeInt64(i int64) (err error) {
	return binary.Write(e.w, binary.LittleEndian, i)
}

func (e *SemaEncoder) EncodeInt32(i int32) (err error) {
	return binary.Write(e.w, binary.LittleEndian, i)
}

func (e *SemaEncoder) EncodeLocation(t common.Location) (err error) {
	switch concreteType := t.(type) {
	case common.AddressLocation:
		return e.EncodeAddressLocation(concreteType)
	case common.IdentifierLocation:
		return e.EncodeIdentifierLocation(concreteType)
	case common.ScriptLocation:
		return e.EncodeScriptLocation(concreteType)
	case common.StringLocation:
		return e.EncodeStringLocation(concreteType)
	case common.TransactionLocation:
		return e.EncodeTransactionLocation(concreteType)
	case common.REPLLocation:
		return e.EncodeREPLLocation()
	default:
		return fmt.Errorf("Unexpected loation type: %s", concreteType)
	}
}

// The location prefixes are stored as strings but are always* a single ascii character,
// so they can be stored in a single byte.
// * The exception is the REPL location but its first ascii character is unique anyway.
func (e *SemaEncoder) EncodeLocationPrefix(prefix string) (err error) {
	char := prefix[0]
	return e.write([]byte{char})
}

func (e *SemaEncoder) EncodeAddressLocation(t common.AddressLocation) (err error) {
	err = e.EncodeLocationPrefix(common.AddressLocationPrefix)
	if err != nil { return }

	err = e.EncodeAddress(t.Address)
	if err != nil { return }

	return e.EncodeString(t.Name)
}

func (e *SemaEncoder) EncodeIdentifierLocation(t common.IdentifierLocation) (err error) {
	err = e.EncodeLocationPrefix(common.IdentifierLocationPrefix)
	if err != nil { return }

	return e.EncodeString(string(t))
}

func (e *SemaEncoder) EncodeScriptLocation(t common.ScriptLocation) (err error) {
	err = e.EncodeLocationPrefix(common.ScriptLocationPrefix)
	if err != nil { return }

	return e.EncodeBytes(t)
}

func (e *SemaEncoder) EncodeStringLocation(t common.StringLocation) (err error) {
	err = e.EncodeLocationPrefix(common.StringLocationPrefix)
	if err != nil { return }

	return e.EncodeString(string(t))
}

func (e *SemaEncoder) EncodeTransactionLocation(t common.TransactionLocation) (err error) {
	err = e.EncodeLocationPrefix(common.TransactionLocationPrefix)
	if err != nil { return }

	return e.EncodeBytes(t)
}

func (e *SemaEncoder) EncodeREPLLocation() (err error) {
	return e.EncodeLocationPrefix(common.REPLLocationPrefix)
}

// TODO need to do anything to handle full range of possible runes?
func (e *SemaEncoder) EncodeString(s string) (err error) {
	err = e.EncodeLength(len(s))
	if err != nil { return }

	for _, c := range s {
		err = e.EncodeCharacter(c)
		if err != nil { return }
	}

	return
}

// EncodeBytes encodes byte arrays.
func (e *SemaEncoder) EncodeBytes(bytes []byte) (err error) {
	err = e.EncodeLength(len(bytes))
	if err != nil { return }

	return e.write(bytes)
}

func (e *SemaEncoder) EncodeCharacter(c rune) (err error) {
	return e.EncodeInt32(c)
}

// EncodeLength encodes a non-negative length as a uint32.
// It uses 4 bytes.
func (e *SemaEncoder) EncodeLength(length int) (err error) {
	if length < 0 { // TODO is this safety check useful?
		return fmt.Errorf("Cannot encode length below zero: %d", length)
	}

	// TODO is type conversion safe here?
	// TODO could type conversion be done cheaper since length is for sure positive?
	l := uint32(length)
	blob := make([]byte, 4)
	binary.LittleEndian.PutUint32(blob, l)

	_, err = e.w.Write(blob)

	return
}

func (e *SemaEncoder) EncodeAddress(address common.Address) (err error) {
	return e.write(address[:])
}

func (e *SemaEncoder) write(b []byte) (err error) {
	_, err = e.w.Write(b)
	return
}