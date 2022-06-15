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
	"github.com/onflow/cadence/runtime/sema"
	"github.com/pkg/errors"
	"io"
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
	err = e.EncodeSimpleType(EncodedTypeVariableSizeArray)
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
		return errors.Errorf("Cannot encode length below zero: %d", length)
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
