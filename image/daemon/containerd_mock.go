package daemon

import (
	"context"
	"io"
	"reflect"

	"github.com/containerd/containerd/content"
	"github.com/golang/mock/gomock"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// MockContainerd ...
type MockContainerd struct {
	ctrl     *gomock.Controller
	recorder *MockContainerdMockRecorder
}

// MockLVMMockRecorder ...
type MockContainerdMockRecorder struct {
	mock *MockContainerd
}

// EXCEPT ...
func (m *MockContainerd) EXCEPT() *MockContainerdMockRecorder {
	return m.recorder
}

func NewMockContainerd(ctrl *gomock.Controller) *MockContainerd {
	mock := &MockContainerd{ctrl: ctrl}
	mock.recorder = &MockContainerdMockRecorder{mock}
	return mock
}

// GetImageConfig ...
func (m *MockContainerd) GetImageConfig(ctx context.Context) (ocispec.Descriptor, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetImageConfig", ctx)
	ret0, _ := ret[0].(ocispec.Descriptor)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockContainerdMockRecorder) GetImageConfig(arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetImageConfig", reflect.TypeOf((*MockContainerd)(nil).GetImageConfig), arg1)
}

// GetImageName ...
func (m *MockContainerd) GetImageName(ctx context.Context) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetImageName", ctx)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetImageName ...
func (mr *MockContainerdMockRecorder) GetImageName(arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetImageName", reflect.TypeOf((*MockContainerd).GetImageName), arg1)
}

// ImageWriter ...
func (m *MockContainerd) ImageWriter(ctx context.Context, ref []string) (io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageWriter", ctx, ref)
	ret0, _ := ret[0].(io.ReadCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockContainerdMockRecorder) ImageWriter(arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageWriter", reflect.TypeOf((*MockContainerd).ImageWriter), arg1, arg2)
}

func (m *MockContainerd) ContentStore(ctx context.Context) (content.Store, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContentStore", ctx)
	ret0, _ := ret[0].(content.Store)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockContainerdMockRecorder) ContentStore(arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContentStore", reflect.TypeOf((*MockContainerd).ContentStore), arg1)
}

func (m *MockContainerd) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

func (mr *MockContainerdMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockContainerd).Close))
}

func (m *MockContainerd) GetOCIImageBytes(ctx context.Context) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOCIImageBytes", ctx)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

func (mr *MockContainerdMockRecorder) GetOCIImageBytes(arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOCIImageBytes", reflect.TypeOf((*MockContainerd).GetOCIImageBytes), arg1)
}
