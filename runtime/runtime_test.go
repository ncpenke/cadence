package runtime

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dapperlabs/flow-go/sdk/abi/values"
)

type testRuntimeInterface struct {
	resolveImport      func(Location) (values.Bytes, error)
	getValue           func(controller, owner, key values.Bytes) (value values.Bytes, err error)
	setValue           func(controller, owner, key, value values.Bytes) (err error)
	createAccount      func(publicKeys []values.Bytes, code values.Bytes) (address values.Address, err error)
	addAccountKey      func(address values.Address, publicKey values.Bytes) error
	removeAccountKey   func(address values.Address, index values.Int) (publicKey values.Bytes, err error)
	updateAccountCode  func(address values.Address, code values.Bytes) (err error)
	getSigningAccounts func() []values.Address
	log                func(string)
	emitEvent          func(values.Event)
}

func (i *testRuntimeInterface) ResolveImport(location Location) (values.Bytes, error) {
	return i.resolveImport(location)
}

func (i *testRuntimeInterface) GetValue(controller, owner, key values.Bytes) (value values.Bytes, err error) {
	return i.getValue(controller, owner, key)
}

func (i *testRuntimeInterface) SetValue(controller, owner, key, value values.Bytes) (err error) {
	return i.setValue(controller, owner, key, value)
}

func (i *testRuntimeInterface) CreateAccount(publicKeys []values.Bytes, code values.Bytes) (address values.Address, err error) {
	return i.createAccount(publicKeys, code)
}

func (i *testRuntimeInterface) AddAccountKey(address values.Address, publicKey values.Bytes) error {
	return i.addAccountKey(address, publicKey)
}

func (i *testRuntimeInterface) RemoveAccountKey(address values.Address, index values.Int) (publicKey values.Bytes, err error) {
	return i.removeAccountKey(address, index)
}

func (i *testRuntimeInterface) UpdateAccountCode(address values.Address, code values.Bytes) (err error) {
	return i.updateAccountCode(address, code)
}

func (i *testRuntimeInterface) GetSigningAccounts() []values.Address {
	if i.getSigningAccounts == nil {
		return nil
	}
	return i.getSigningAccounts()
}

func (i *testRuntimeInterface) Log(message string) {
	i.log(message)
}

func (i *testRuntimeInterface) EmitEvent(event values.Event) {
	i.emitEvent(event)
}

func TestRuntimeImport(t *testing.T) {

	runtime := NewInterpreterRuntime()

	importedScript := []byte(`
      pub fun answer(): Int {
	    return 42
      }
	`)

	script := []byte(`
	  import "imported"

	  pub fun main(): Int {
	  	let answer = answer()
		  if answer != 42 {
			panic("?!")
		  }
		  return answer
		}
	`)

	runtimeInterface := &testRuntimeInterface{
		resolveImport: func(location Location) (bytes values.Bytes, err error) {
			switch location {
			case StringLocation("imported"):
				return importedScript, nil
			default:
				return nil, fmt.Errorf("unknown import location: %s", location)
			}
		},
	}

	value, err := runtime.ExecuteScript(script, runtimeInterface, nil)
	assert.NoError(t, err)
	assert.Equal(t, values.NewInt(42), value)
}

func TestRuntimeInvalidTransactionArgumentAccount(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script := []byte(`
	  transaction {
	    prepare() {}
	    execute {}
	  }
	`)

	runtimeInterface := &testRuntimeInterface{
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
	}

	err := runtime.ExecuteTransaction(script, runtimeInterface, nil)
	assert.Error(t, err)
}

func TestRuntimeTransactionWithAccount(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script := []byte(`
	  transaction {
	    prepare(signer: Account) {
		  log(signer.address)
		}
	    execute {}
	  }
	`)

	var loggedMessage string

	runtimeInterface := &testRuntimeInterface{
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return nil, nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessage = message
		},
	}

	err := runtime.ExecuteTransaction(script, runtimeInterface, nil)

	assert.NoError(t, err)
	assert.Equal(t, "2a00000000000000000000000000000000000000", loggedMessage)
}

func TestRuntimeProgramWithNoTransaction(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script := []byte(`
	  pub fun main() {}
	`)

	runtimeInterface := &testRuntimeInterface{}

	err := runtime.ExecuteTransaction(script, runtimeInterface, nil)

	if assert.IsType(t, Error{}, err) {
		err := err.(Error)
		assert.IsType(t, InvalidTransactionCountError{}, err.Unwrap())
	}
}

func TestRuntimeProgramWithMultipleTransaction(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script := []byte(`
	  transaction {
	    execute {}
	  }
	  transaction {
	    execute {}
	  }
	`)

	runtimeInterface := &testRuntimeInterface{}

	err := runtime.ExecuteTransaction(script, runtimeInterface, nil)

	if assert.IsType(t, Error{}, err) {
		err := err.(Error)
		assert.IsType(t, InvalidTransactionCountError{}, err.Unwrap())
	}
}

func TestRuntimeStorage(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script := []byte(`
	  transaction {
	    prepare(signer: Account) {
		  log(signer.storage[Int])

		  signer.storage[Int] = 42
		  log(signer.storage[Int])

		  signer.storage[[Int]] = [1, 2, 3]
		  log(signer.storage[[Int]])

		  signer.storage[String] = "xyz"
		  log(signer.storage[String])
		}
	    execute {}
	  }
	`)

	storedValues := map[string][]byte{}

	var loggedMessages []string

	runtimeInterface := &testRuntimeInterface{
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script, runtimeInterface, nil)
	require.NoError(t, err)

	assert.Equal(t, []string{"nil", "42", "[1, 2, 3]", `"xyz"`}, loggedMessages)
}

func TestRuntimeStorageMultipleTransactionsArray(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script1 := []byte(`
	  transaction {
	    prepare(signer: Account) {
		  log(signer.storage[[String]])
		  signer.storage[[String]] = []
		}
	    execute {}
	  }
	`)

	script2 := []byte(`
	  transaction {
	    prepare(signer: Account) {
		  log(signer.storage[[String]])
		  signer.storage[[String]] = ["A", "B"]
		}
	    execute {}
	  }
	`)

	var loggedMessages []string
	storedValues := map[string]values.Bytes{}

	runtimeInterface := &testRuntimeInterface{
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	require.NoError(t, err)

	err = runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	require.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	require.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	require.NoError(t, err)

	assert.Equal(t, []string{"nil", `[]`, `[]`, `["A", "B"]`}, loggedMessages)
}

func TestRuntimeStorageMultipleTransactionsDictionary(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script1 := []byte(`
	  transaction {
	    prepare(signer: Account) {
		  log(signer.storage[{String: Int}])
		  signer.storage[{String: Int}] = {}
		}
	    execute {}
	  }
	`)

	script2 := []byte(`
	  transaction {
	    prepare(signer: Account) {
		  log(signer.storage[{String: Int}])
		  signer.storage[{String: Int}] = {"A": 1, "B": 2}
		}
	    execute {}
	  }
	`)

	var loggedMessages []string
	storedValues := map[string]values.Bytes{}

	runtimeInterface := &testRuntimeInterface{
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	require.NoError(t, err)

	err = runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	require.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	require.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	require.NoError(t, err)

	// Assertion is a bit more complex, because dictionary order is not deterministic
	require.Len(t, loggedMessages, 4)
	assert.Equal(t, []string{"nil", `{}`, `{}`}, loggedMessages[:3])
	assert.Contains(t, []string{`{"A": 1, "B": 2}`, `{"B": 2, "A": 1}`}, loggedMessages[3])
}

func TestRuntimeStorageMultipleTransactionsStructureAndArray(t *testing.T) {
	runtime := NewInterpreterRuntime()

	container := []byte(`
	  pub resource Container {
		pub let values: [Int]

		init() {
		  self.values = []
		}
	  }

	  pub fun createContainer(): <-Container {
		return <-create Container()
	  }
	`)

	script1 := []byte(`
	  import "container"

	  transaction {
	    prepare(signer: Account) {
		  var container: <-Container? <- createContainer()
		  signer.storage[Container] <-> container
		  destroy container
		  let ref = &signer.storage[Container] as Container
		  signer.storage[&Container] = ref
		}
		execute {}
	  }
	`)

	script2 := []byte(`
	  import "container"

	  transaction {
	    prepare(signer: Account) {
          let ref = signer.storage[&Container] ?? panic("no container")
          let length = ref.values.length
          ref.values.append(1)
          let length2 = ref.values.length
		}
		execute {}
	  }
	`)

	script3 := []byte(`
	  import "container"

	  transaction {
	    prepare(signer: Account) {
          let ref = signer.storage[&Container] ?? panic("no container")
          let length = ref.values.length
          ref.values.append(2)
          let length2 = ref.values.length
		}
		execute {}
	  }
	`)

	var loggedMessages []string
	storedValues := map[string]values.Bytes{}

	runtimeInterface := &testRuntimeInterface{
		resolveImport: func(location Location) (bytes values.Bytes, err error) {
			switch location {
			case StringLocation("container"):
				return container, nil
			default:
				return nil, fmt.Errorf("unknown import location: %s", location)
			}
		},
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	require.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	require.NoError(t, err)

	err = runtime.ExecuteTransaction(script3, runtimeInterface, nil)
	require.NoError(t, err)
}

// TestRuntimeStorageMultipleTransactionsStructures tests a function call
// of a stored structure declared in an imported program
//
func TestRuntimeStorageMultipleTransactionsStructures(t *testing.T) {
	runtime := NewInterpreterRuntime()

	deepThought := []byte(`
	  pub struct DeepThought {

		pub fun answer(): Int {
		  return 42
		}
	  }
	`)

	script1 := []byte(`
	  import "deep-thought"

	  transaction {
	    prepare(signer: Account) {
		  signer.storage[DeepThought] = DeepThought()

		  log(signer.storage[DeepThought])
		}
		execute {}
	  }
	`)

	script2 := []byte(`
	  import "deep-thought"

	  transaction {
	    prepare(signer: Account) {
		  log(signer.storage[DeepThought])

		  let computer = signer.storage[DeepThought]
		    ?? panic("missing computer")

		  let answer = computer.answer()
		  log(answer)
		}
		execute {}
	  }
	`)

	var loggedMessages []string
	storedValues := map[string]values.Bytes{}

	runtimeInterface := &testRuntimeInterface{
		resolveImport: func(location Location) (bytes values.Bytes, err error) {
			switch location {
			case StringLocation("deep-thought"):
				return deepThought, nil
			default:
				return nil, fmt.Errorf("unknown import location: %s", location)
			}
		},
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	assert.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	assert.NoError(t, err)

	assert.Contains(t, loggedMessages, "42")
}

func TestRuntimeStorageMultipleTransactionsInt(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script1 := []byte(`
	  transaction {
	    prepare(signer: Account) {
	      signer.storage[Int] = 42
		}
		execute {}
	  }
	`)

	script2 := []byte(`
	  transaction {
	    prepare(signer: Account) {
	      let x = signer.storage[Int] ?? panic("stored value is nil")
		  log(x)
		}
		execute {}
	  }
	`)

	var loggedMessages []string
	storedValues := map[string]values.Bytes{}

	runtimeInterface := &testRuntimeInterface{
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	assert.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	assert.NoError(t, err)

	assert.Contains(t, loggedMessages, "42")
}

// TestRuntimeCompositeFunctionInvocationFromImportingProgram checks
// that member functions of imported composites can be invoked from an importing program.
// See https://github.com/dapperlabs/flow-go/issues/838
//
func TestRuntimeCompositeFunctionInvocationFromImportingProgram(t *testing.T) {
	runtime := NewInterpreterRuntime()

	imported := []byte(`
      // function must have arguments
      pub fun x(x: Int) {}

      // invocation must be in composite
      pub struct Y {
	    pub fun x() {
		  x(x: 1)
		}
      }
    `)

	script1 := []byte(`
      import Y from "imported"

	  transaction {
	    prepare(signer: Account) {
	      signer.storage[Y] = Y()
		}
		execute {}
	  }
    `)

	script2 := []byte(`
      import Y from "imported"

	  transaction {
	    prepare(signer: Account) {
          let y = signer.storage[Y] ?? panic("stored value is nil")
          y.x()
		}
		execute {}
	  }
    `)

	storedValues := map[string]values.Bytes{}

	runtimeInterface := &testRuntimeInterface{
		resolveImport: func(location Location) (bytes values.Bytes, err error) {
			switch location {
			case StringLocation("imported"):
				return imported, nil
			default:
				return nil, fmt.Errorf("unknown import location: %s", location)
			}
		},
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	assert.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	assert.NoError(t, err)
}

func TestRuntimeResourceContractUseThroughReference(t *testing.T) {
	runtime := NewInterpreterRuntime()

	imported := []byte(`
      pub resource R {
		pub fun x() {
		  log("x!")
		}
      }

      pub fun createR(): <-R {
		return <- create R()
      }
    `)

	script1 := []byte(`
      import R, createR from "imported"

	  transaction {
	    prepare(signer: Account) {
          var r: <-R? <- createR()
	      signer.storage[R] <-> r
          if r != nil {
             panic("already initialized")
          }
          destroy r
		}
		execute {}
	  }
    `)

	script2 := []byte(`
      import R from "imported"

	  transaction {
	    prepare(signer: Account) {
          let ref = &signer.storage[R] as R
          ref.x()
		}
		execute {}
	  }
    `)

	storedValues := map[string][]byte{}

	var loggedMessages []string

	runtimeInterface := &testRuntimeInterface{
		resolveImport: func(location Location) (bytes values.Bytes, err error) {
			switch location {
			case StringLocation("imported"):
				return imported, nil
			default:
				return nil, fmt.Errorf("unknown import location: %s", location)
			}
		},
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	assert.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	assert.NoError(t, err)

	assert.Equal(t, []string{"\"x!\""}, loggedMessages)
}

func TestRuntimeResourceContractUseThroughStoredReference(t *testing.T) {
	runtime := NewInterpreterRuntime()

	imported := []byte(`
      pub resource R {
		pub fun x() {
		  log("x!")
		}
      }

      pub fun createR(): <-R {
  		return <- create R()
      }
    `)

	script1 := []byte(`
      import R, createR from "imported"

	  transaction {
	    prepare(signer: Account) {
          var r: <-R? <- createR()
	      signer.storage[R] <-> r
          if r != nil {
 			panic("already initialized")
          }
          destroy r

          signer.storage[&R] = &signer.storage[R] as R
		}
		execute {}
	  }
    `)

	script2 := []byte(`
	  import R from "imported"

	  transaction {
	    prepare(signer: Account) {
	      let ref = signer.storage[&R] ?? panic("no R ref")
	      ref.x()
		}
		execute {}
	  }
	`)

	storedValues := map[string][]byte{}

	var loggedMessages []string

	runtimeInterface := &testRuntimeInterface{
		resolveImport: func(location Location) (bytes values.Bytes, err error) {
			switch location {
			case StringLocation("imported"):
				return imported, nil
			default:
				return nil, fmt.Errorf("unknown import location: %s", location)
			}
		},
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	assert.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	assert.NoError(t, err)

	assert.Equal(t, []string{"\"x!\""}, loggedMessages)
}

func TestRuntimeResourceContractWithInterface(t *testing.T) {
	runtime := NewInterpreterRuntime()

	imported1 := []byte(`
      pub resource interface RI {
		pub fun x()
      }
    `)

	imported2 := []byte(`
      import RI from "imported1"

      pub resource R: RI {
		pub fun x() {
		  log("x!")
		}
      }

      pub fun createR(): <-R {
		return <- create R()
      }
    `)

	script1 := []byte(`
	  import RI from "imported1"
      import R, createR from "imported2"

	  transaction {
	    prepare(signer: Account) {
          var r: <-R? <- createR()
	      signer.storage[R] <-> r
          if r != nil {
			panic("already initialized")
          }
          destroy r

          signer.storage[&RI] = &signer.storage[R] as RI
		}
		execute {}
	  }
    `)

	// TODO: Get rid of the requirement that the underlying type must be imported.
	//   This requires properly initializing Interpreter.CompositeFunctions.
	//   Also initialize Interpreter.DestructorFunctions

	script2 := []byte(`
	  import RI from "imported1"
      import R from "imported2"

	  transaction {
	    prepare(signer: Account) {
	      let ref = signer.storage[&RI] ?? panic("no RI ref")
	      ref.x()
		}
		execute {}
	  }
	`)

	storedValues := map[string][]byte{}

	var loggedMessages []string

	runtimeInterface := &testRuntimeInterface{
		resolveImport: func(location Location) (bytes values.Bytes, err error) {
			switch location {
			case StringLocation("imported1"):
				return imported1, nil
			case StringLocation("imported2"):
				return imported2, nil
			default:
				return nil, fmt.Errorf("unknown import location: %s", location)
			}
		},
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	assert.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	assert.NoError(t, err)

	assert.Equal(t, []string{"\"x!\""}, loggedMessages)
}

func TestParseAndCheckProgram(t *testing.T) {
	t.Run("ValidProgram", func(t *testing.T) {
		runtime := NewInterpreterRuntime()

		script := []byte("pub fun test(): Int { return 42 }")
		runtimeInterface := &testRuntimeInterface{}

		err := runtime.ParseAndCheckProgram(script, runtimeInterface, nil)
		assert.NoError(t, err)
	})

	t.Run("InvalidSyntax", func(t *testing.T) {
		runtime := NewInterpreterRuntime()

		script := []byte("invalid syntax")
		runtimeInterface := &testRuntimeInterface{}

		err := runtime.ParseAndCheckProgram(script, runtimeInterface, nil)
		assert.NotNil(t, err)
	})

	t.Run("InvalidSemantics", func(t *testing.T) {
		runtime := NewInterpreterRuntime()

		script := []byte(`pub let a: Int = "b"`)
		runtimeInterface := &testRuntimeInterface{}

		err := runtime.ParseAndCheckProgram(script, runtimeInterface, nil)
		assert.NotNil(t, err)
	})
}

func TestRuntimeSyntaxError(t *testing.T) {
	runtime := NewInterpreterRuntime()

	script := []byte(`
      pub fun main(): String {
	  	return "Hello World!
      }
	`)

	runtimeInterface := &testRuntimeInterface{
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
	}

	_, err := runtime.ExecuteScript(script, runtimeInterface, nil)
	assert.Error(t, err)
}

func TestRuntimeStorageChanges(t *testing.T) {
	runtime := NewInterpreterRuntime()

	imported := []byte(`
      pub resource X {
	    pub(set) var x: Int
	
	    init() {
		  self.x = 0
	    }
      }

      pub fun createX(): <-X {
	  	return <-create X()
      }
    `)

	script1 := []byte(`
	  import X, createX from "imported"

	  transaction {
	    prepare(signer: Account) {
          var x: <-X? <- createX()
          signer.storage[X] <-> x
          destroy x

          let ref = &signer.storage[X] as X
          ref.x = 1
		}
		execute {}
	  }
    `)

	script2 := []byte(`
	  import X from "imported"

	  transaction {
	    prepare(signer: Account) {
	      let ref = &signer.storage[X] as X
          log(ref.x)
		}
		execute {}
	  }
	`)

	storedValues := map[string][]byte{}

	var loggedMessages []string

	runtimeInterface := &testRuntimeInterface{
		resolveImport: func(location Location) (bytes values.Bytes, err error) {
			switch location {
			case StringLocation("imported"):
				return imported, nil
			default:
				return nil, fmt.Errorf("unknown import location: %s", location)
			}
		},
		getValue: func(controller, owner, key values.Bytes) (value values.Bytes, err error) {
			return storedValues[string(key)], nil
		},
		setValue: func(controller, owner, key, value values.Bytes) (err error) {
			storedValues[string(key)] = value
			return nil
		},
		getSigningAccounts: func() []values.Address {
			return []values.Address{[20]byte{42}}
		},
		log: func(message string) {
			loggedMessages = append(loggedMessages, message)
		},
	}

	err := runtime.ExecuteTransaction(script1, runtimeInterface, nil)
	assert.NoError(t, err)

	err = runtime.ExecuteTransaction(script2, runtimeInterface, nil)
	assert.NoError(t, err)

	assert.Equal(t, []string{"1"}, loggedMessages)
}
