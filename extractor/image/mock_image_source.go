// Code generated by mockery v1.0.0. DO NOT EDIT.

package image

import context "context"
import io "io"
import mock "github.com/stretchr/testify/mock"
import types "github.com/containers/image/v5/types"

// MockImageSource is an autogenerated mock type for the ImageSource type
type MockImageSource struct {
	mock.Mock
}

type GetBlobArgs struct {
	Ctx           context.Context
	CtxAnything   bool
	Info          types.BlobInfo
	InfoAnything  bool
	Cache         types.BlobInfoCache
	CacheAnything bool
}

type GetBlobReturns struct {
	Reader io.ReadCloser
	N      int64
	Err    error
}

type GetBlobExpectation struct {
	Args    GetBlobArgs
	Returns GetBlobReturns
}

func (_m *MockImageSource) ApplyGetBlobExpectation(e GetBlobExpectation) {
	var args []interface{}
	if e.Args.CtxAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Ctx)
	}
	if e.Args.InfoAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Info)
	}
	if e.Args.CacheAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Cache)
	}
	_m.On("GetBlob", args...).Return(e.Returns.Reader, e.Returns.N, e.Returns.Err)
}

func (_m *MockImageSource) ApplyGetBlobExpectations(expectations []GetBlobExpectation) {
	for _, e := range expectations {
		_m.ApplyGetBlobExpectation(e)
	}
}

// GetBlob provides a mock function with given fields: ctx, info, cache
func (_m *MockImageSource) GetBlob(ctx context.Context, info types.BlobInfo, cache types.BlobInfoCache) (io.ReadCloser, int64, error) {
	ret := _m.Called(ctx, info, cache)

	var r0 io.ReadCloser
	if rf, ok := ret.Get(0).(func(context.Context, types.BlobInfo, types.BlobInfoCache) io.ReadCloser); ok {
		r0 = rf(ctx, info, cache)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(io.ReadCloser)
		}
	}

	var r1 int64
	if rf, ok := ret.Get(1).(func(context.Context, types.BlobInfo, types.BlobInfoCache) int64); ok {
		r1 = rf(ctx, info, cache)
	} else {
		r1 = ret.Get(1).(int64)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(context.Context, types.BlobInfo, types.BlobInfoCache) error); ok {
		r2 = rf(ctx, info, cache)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}