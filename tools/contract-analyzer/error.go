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

package main

import (
	"fmt"

	"github.com/logrusorgru/aurora"
	"github.com/onflow/cadence/tools/analysis"
)

type diagnosticErr struct {
	analysis.Diagnostic
}

var _ error = diagnosticErr{}

func (d diagnosticErr) Error() string {
	return fmt.Sprintf("%s: %s", d.Category, d.Message)
}

func (d diagnosticErr) SecondaryError() string {
	return d.SecondaryMessage
}

func (d diagnosticErr) Prefix() string {
	return d.Category
}

func (d diagnosticErr) Color() aurora.Color {
	return aurora.YellowFg
}
