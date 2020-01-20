// Code generated by mockery v1.0.0. DO NOT EDIT.

package cache

import io "io"
import mock "github.com/stretchr/testify/mock"

// MockCache is an autogenerated mock type for the Cache type
type MockCache struct {
	mock.Mock
}

type ClearReturns struct {
	Err error
}

type ClearExpectation struct {
	Returns ClearReturns
}

func (_m *MockCache) ApplyClearExpectation(e ClearExpectation) {
	var args []interface{}
	_m.On("Clear", args...).Return(e.Returns.Err)
}

func (_m *MockCache) ApplyClearExpectations(expectations []ClearExpectation) {
	for _, e := range expectations {
		_m.ApplyClearExpectation(e)
	}
}

// Clear provides a mock function with given fields:
func (_m *MockCache) Clear() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type GetArgs struct {
	Key         string
	KeyAnything bool
}

type GetReturns struct {
	Reader io.ReadCloser
}

type GetExpectation struct {
	Args    GetArgs
	Returns GetReturns
}

func (_m *MockCache) ApplyGetExpectation(e GetExpectation) {
	var args []interface{}
	if e.Args.KeyAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Key)
	}
	_m.On("Get", args...).Return(e.Returns.Reader)
}

func (_m *MockCache) ApplyGetExpectations(expectations []GetExpectation) {
	for _, e := range expectations {
		_m.ApplyGetExpectation(e)
	}
}

// Get provides a mock function with given fields: key
func (_m *MockCache) Get(key string) io.ReadCloser {
	ret := _m.Called(key)

	var r0 io.ReadCloser
	if rf, ok := ret.Get(0).(func(string) io.ReadCloser); ok {
		r0 = rf(key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.ReadCloser)
		}
	}

	return r0
}

type SetArgs struct {
	Key          string
	KeyAnything  bool
	File         io.Reader
	FileAnything bool
}

type SetReturns struct {
	Reader io.Reader
	Err    error
}

type SetExpectation struct {
	Args    SetArgs
	Returns SetReturns
}

func (_m *MockCache) ApplySetExpectation(e SetExpectation) {
	var args []interface{}
	if e.Args.KeyAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Key)
	}
	if e.Args.FileAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.File)
	}
	_m.On("Set", args...).Return(e.Returns.Reader, e.Returns.Err)
}

func (_m *MockCache) ApplySetExpectations(expectations []SetExpectation) {
	for _, e := range expectations {
		_m.ApplySetExpectation(e)
	}
}

// Set provides a mock function with given fields: key, file
func (_m *MockCache) Set(key string, file io.Reader) (io.Reader, error) {
	ret := _m.Called(key, file)

	var r0 io.Reader
	if rf, ok := ret.Get(0).(func(string, io.Reader) io.Reader); ok {
		r0 = rf(key, file)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.Reader)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, io.Reader) error); ok {
		r1 = rf(key, file)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type SetBytesArgs struct {
	Key           string
	KeyAnything   bool
	Value         []byte
	ValueAnything bool
}

type SetBytesReturns struct {
	Err error
}

type SetBytesExpectation struct {
	Args    SetBytesArgs
	Returns SetBytesReturns
}

func (_m *MockCache) ApplySetBytesExpectation(e SetBytesExpectation) {
	var args []interface{}
	if e.Args.KeyAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Key)
	}
	if e.Args.ValueAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Value)
	}
	_m.On("SetBytes", args...).Return(e.Returns.Err)
}

func (_m *MockCache) ApplySetBytesExpectations(expectations []SetBytesExpectation) {
	for _, e := range expectations {
		_m.ApplySetBytesExpectation(e)
	}
}

// SetBytes provides a mock function with given fields: key, value
func (_m *MockCache) SetBytes(key string, value []byte) error {
	ret := _m.Called(key, value)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, []byte) error); ok {
		r0 = rf(key, value)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
