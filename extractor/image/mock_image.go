// Code generated by mockery v1.0.0. DO NOT EDIT.

package image

import context "context"
import digest "github.com/opencontainers/go-digest"
import io "io"
import mock "github.com/stretchr/testify/mock"
import types "github.com/containers/image/v5/types"

// MockImage is an autogenerated mock type for the Image type
type MockImage struct {
	mock.Mock
}

type ConfigReturns struct {
	_a0 types.BlobInfo
}

type ConfigExpectation struct {
	Returns ConfigReturns
}

func (_m *MockImage) ApplyConfigExpectation(e ConfigExpectation) {
	var args []interface{}
	_m.On("Config", args...).Return(e.Returns._a0)
}

func (_m *MockImage) ApplyConfigExpectations(expectations []ConfigExpectation) {
	for _, e := range expectations {
		_m.ApplyConfigExpectation(e)
	}
}

// Config provides a mock function with given fields:
func (_m *MockImage) Config() types.BlobInfo {
	ret := _m.Called()

	var r0 types.BlobInfo
	if rf, ok := ret.Get(0).(func() types.BlobInfo); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(types.BlobInfo)
	}

	return r0
}

type GetLayerArgs struct {
	Ctx         context.Context
	CtxAnything bool
	Dig         digest.Digest
	DigAnything bool
}

type GetLayerReturns struct {
	Reader io.ReadCloser
	Err    error
}

type GetLayerExpectation struct {
	Args    GetLayerArgs
	Returns GetLayerReturns
}

func (_m *MockImage) ApplyGetLayerExpectation(e GetLayerExpectation) {
	var args []interface{}
	if e.Args.CtxAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Ctx)
	}
	if e.Args.DigAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Dig)
	}
	_m.On("GetLayer", args...).Return(e.Returns.Reader, e.Returns.Err)
}

func (_m *MockImage) ApplyGetLayerExpectations(expectations []GetLayerExpectation) {
	for _, e := range expectations {
		_m.ApplyGetLayerExpectation(e)
	}
}

// GetLayer provides a mock function with given fields: ctx, dig
func (_m *MockImage) GetLayer(ctx context.Context, dig digest.Digest) (io.ReadCloser, error) {
	ret := _m.Called(ctx, dig)

	var r0 io.ReadCloser
	if rf, ok := ret.Get(0).(func(context.Context, digest.Digest) io.ReadCloser); ok {
		r0 = rf(ctx, dig)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.ReadCloser)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, digest.Digest) error); ok {
		r1 = rf(ctx, dig)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type LayerIDsReturns struct {
	LayerIDs []string
}

type LayerIDsExpectation struct {
	Returns LayerIDsReturns
}

func (_m *MockImage) ApplyLayerIDsExpectation(e LayerIDsExpectation) {
	var args []interface{}
	_m.On("LayerIDs", args...).Return(e.Returns.LayerIDs)
}

func (_m *MockImage) ApplyLayerIDsExpectations(expectations []LayerIDsExpectation) {
	for _, e := range expectations {
		_m.ApplyLayerIDsExpectation(e)
	}
}

// LayerIDs provides a mock function with given fields:
func (_m *MockImage) LayerIDs() []string {
	ret := _m.Called()

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

type NameReturns struct {
	Name string
}

type NameExpectation struct {
	Returns NameReturns
}

func (_m *MockImage) ApplyNameExpectation(e NameExpectation) {
	var args []interface{}
	_m.On("Name", args...).Return(e.Returns.Name)
}

func (_m *MockImage) ApplyNameExpectations(expectations []NameExpectation) {
	for _, e := range expectations {
		_m.ApplyNameExpectation(e)
	}
}

// Name provides a mock function with given fields:
func (_m *MockImage) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}
