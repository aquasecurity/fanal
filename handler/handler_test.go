package handler_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/handler"
	"github.com/aquasecurity/fanal/types"
)

type fakeHook struct{}

func (h fakeHook) Version() int { return 1 }

func (h fakeHook) Type() handler.Type { return "fake" }

func (h fakeHook) Handle(info *types.BlobInfo) error {
	info.DiffID = "fake"
	return nil
}

func TestManager_Versions(t *testing.T) {
	tests := []struct {
		name    string
		disable []handler.Type
		want    map[string]int
	}{
		{
			name: "happy path",
			want: map[string]int{
				"fake": 1,
			},
		},
		{
			name:    "disable hooks",
			disable: []handler.Type{"fake"},
			want: map[string]int{
				"fake": 0,
			},
		},
	}

	handler.RegisterPostHandler(fakeHook{})
	defer handler.DeregisterPostHandler("fake")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := handler.NewManager(tt.disable)
			got := m.Versions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestManager_CallHooks(t *testing.T) {
	tests := []struct {
		name    string
		disable []handler.Type
		want    types.BlobInfo
	}{
		{
			name: "happy path",
			want: types.BlobInfo{
				Digest: "digest",
				DiffID: "fake",
			},
		},
		{
			name:    "disable hooks",
			disable: []handler.Type{"fake"},
			want: types.BlobInfo{
				Digest: "digest",
			},
		},
	}

	handler.RegisterPostHandler(fakeHook{})
	defer handler.DeregisterPostHandler("fake")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob := types.BlobInfo{
				Digest: "digest",
			}
			m := handler.NewManager(tt.disable)

			err := m.CallHooks(&blob)
			require.NoError(t, err)
			assert.Equal(t, tt.want, blob)
		})
	}
}
