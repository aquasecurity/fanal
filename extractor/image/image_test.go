package image

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"testing"

	"github.com/opencontainers/go-digest"

	imageTypes "github.com/containers/image/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

func TestNewImage(t *testing.T) {
	type args struct {
		image      Reference
		transports []string
		option     types.DockerOption
	}
	type image struct {
		name       string
		isFile     bool
		transports []string
	}
	tests := []struct {
		name              string
		args              args
		wantImage         image
		wantSystemContext *imageTypes.SystemContext
		wantErr           string
	}{
		{
			name: "happy path",
			args: args{
				image: Reference{
					Name:   "alpine:3.10",
					IsFile: false,
				},
				transports: []string{"docker-daemon:"},
				option: types.DockerOption{
					SkipPing:              true,
					InsecureSkipTLSVerify: true,
				},
			},
			wantImage: image{
				name:       "docker.io/library/alpine:3.10",
				isFile:     false,
				transports: []string{"docker-daemon:"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                          "linux",
				OCIInsecureSkipTLSVerify:          true,
				DockerInsecureSkipTLSVerify:       imageTypes.NewOptionalBool(true),
				DockerDisableV1Ping:               true,
				DockerDaemonInsecureSkipTLSVerify: true,
			},
		},
		{
			name: "happy path without latest tag",
			args: args{
				image: Reference{
					Name:   "alpine",
					IsFile: false,
				},
				transports: []string{"docker-daemon:"},
			},
			wantImage: image{
				name:       "docker.io/library/alpine:latest",
				isFile:     false,
				transports: []string{"docker-daemon:"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                    "linux",
				DockerInsecureSkipTLSVerify: imageTypes.NewOptionalBool(false),
			},
		},
		{
			name: "happy path with quay.io",
			args: args{
				image: Reference{
					Name:   "quay.io/prometheus/node-exporter:v0.18.1",
					IsFile: false,
				},
				transports: []string{"docker-daemon:", "docker://"},
			},
			wantImage: image{
				name:       "quay.io/prometheus/node-exporter:v0.18.1",
				isFile:     false,
				transports: []string{"docker-daemon:", "docker://"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                    "linux",
				DockerInsecureSkipTLSVerify: imageTypes.NewOptionalBool(false),
			},
		},
		{
			name: "happy path with a tar file",
			args: args{
				image: Reference{
					Name:   "/tmp/alpine-3.10.tar",
					IsFile: true,
				},
				transports: []string{"docker-archive:"},
			},
			wantImage: image{
				name:       "/tmp/alpine-3.10.tar",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                    "linux",
				DockerInsecureSkipTLSVerify: imageTypes.NewOptionalBool(false),
			},
		},
		{
			name: "sad path: invalid image name",
			args: args{
				image: Reference{
					Name:   "ALPINE",
					IsFile: false,
				},
				transports: []string{"docker-archive:"},
			},
			wantImage: image{
				name:       "/tmp/alpine-3.10.tar",
				isFile:     true,
				transports: []string{"docker-archive:"},
			},
			wantSystemContext: &imageTypes.SystemContext{
				OSChoice:                    "linux",
				DockerInsecureSkipTLSVerify: imageTypes.NewOptionalBool(false),
			},
			wantErr: "invalid image name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := NewImage(ctx, tt.args.image, tt.args.transports, tt.args.option, nil)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.wantSystemContext, got.systemContext, tt.name)
			assert.Equal(t, tt.wantImage.name, got.name, tt.name)
			assert.Equal(t, tt.wantImage.isFile, got.isFile, tt.name)
			assert.Equal(t, tt.wantImage.transports, got.transports, tt.name)
		})
	}
}

func TestImage_LayerInfos(t *testing.T) {
	type fields struct {
		name   string
		isFile bool
	}
	tests := []struct {
		name          string
		fields        fields
		cacheGet      []cache.GetExpectation
		cacheSetBytes []cache.SetBytesExpectation
		srcLayerInfos []LayerInfosExpectation
		want          []imageTypes.BlobInfo
		wantErr       string
	}{
		{
			name: "happy path without cache",
			fields: fields{
				name:   "docker.io/library/alpine:3.10",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "layerinfos::docker.io/library/alpine:3.10",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSetBytes: []cache.SetBytesExpectation{
				{
					Args: cache.SetBytesArgs{
						Key:           "layerinfos::docker.io/library/alpine:3.10",
						ValueAnything: true,
					},
					Returns: cache.SetBytesReturns{Err: nil},
				},
			},
			srcLayerInfos: []LayerInfosExpectation{
				{
					Returns: LayerInfosReturns{
						LayerInfos: []imageTypes.BlobInfo{
							{
								Size:   100,
								Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
							},
						},
					},
				},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:   100,
					Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
				},
			},
		},
		{
			name: "happy path with cache",
			fields: fields{
				name:   "docker.io/library/alpine:3.11",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "layerinfos::docker.io/library/alpine:3.11",
					},
					Returns: cache.GetReturns{Reader: ioutil.NopCloser(
						bytes.NewBuffer([]byte(`[{"Digest":"sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f","Size":2801778,"MediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip"}]`)),
					),
					},
				},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:      2801778,
					Digest:    "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				},
			},
		},
		{
			name: "happy path: cache.Get returns an error, but it is ignored",
			fields: fields{
				name:   "docker.io/library/alpine:3.11",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "layerinfos::docker.io/library/alpine:3.11",
					},
					Returns: cache.GetReturns{Reader: ioutil.NopCloser(
						bytes.NewBuffer([]byte(`[{"invalid"}]`)),
					),
					},
				},
			},
			cacheSetBytes: []cache.SetBytesExpectation{
				{
					Args: cache.SetBytesArgs{
						Key:           "layerinfos::docker.io/library/alpine:3.11",
						ValueAnything: true,
					},
					Returns: cache.SetBytesReturns{Err: nil},
				},
			},
			srcLayerInfos: []LayerInfosExpectation{
				{
					Returns: LayerInfosReturns{
						LayerInfos: []imageTypes.BlobInfo{
							{
								Size:   100,
								Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
							},
						},
					},
				},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:   100,
					Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
				},
			},
		},
		{
			name: "happy path: cache.SetBytes returns an error, but it is ignored",
			fields: fields{
				name:   "docker.io/library/alpine:3.11",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "layerinfos::docker.io/library/alpine:3.11",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSetBytes: []cache.SetBytesExpectation{
				{
					Args: cache.SetBytesArgs{
						Key:           "layerinfos::docker.io/library/alpine:3.11",
						ValueAnything: true,
					},
					Returns: cache.SetBytesReturns{Err: xerrors.New("error")},
				},
			},
			srcLayerInfos: []LayerInfosExpectation{
				{
					Returns: LayerInfosReturns{
						LayerInfos: []imageTypes.BlobInfo{
							{
								Size:   100,
								Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
							},
						},
					},
				},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:   100,
					Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
				},
			},
		},
		{
			name: "happy path: tar file",
			fields: fields{
				name:   "/workspace/alpine-3.10.tar",
				isFile: true,
			},
			srcLayerInfos: []LayerInfosExpectation{
				{
					Returns: LayerInfosReturns{
						LayerInfos: []imageTypes.BlobInfo{
							{
								Size:   100,
								Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
							},
						},
					},
				},
			},
			want: []imageTypes.BlobInfo{
				{
					Size:   100,
					Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockCache)
			c.ApplyGetExpectations(tt.cacheGet)
			c.ApplySetBytesExpectations(tt.cacheSetBytes)

			rawSource := new(MockImageSource)

			src := new(MockImageCloser)
			src.ApplyLayerInfosExpectations(tt.srcLayerInfos)

			img := &Image{
				name:      tt.fields.name,
				isFile:    tt.fields.isFile,
				rawSource: rawSource,
				src:       src,
				cache:     c,
			}
			got, err := img.LayerInfos()
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got, tt.name)

			c.AssertExpectations(t)
			rawSource.AssertExpectations(t)
			src.AssertExpectations(t)
		})
	}
}

func TestImage_ConfigBlob(t *testing.T) {
	type fields struct {
		name   string
		isFile bool
	}
	tests := []struct {
		name          string
		fields        fields
		cacheGet      []cache.GetExpectation
		cacheSetBytes []cache.SetBytesExpectation
		configBlob    []ConfigBlobExpectation
		want          []byte
		wantErr       string
	}{
		{
			name: "happy path without cache",
			fields: fields{
				name:   "docker.io/library/alpine:3.10",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "configblob::docker.io/library/alpine:3.10",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSetBytes: []cache.SetBytesExpectation{
				{
					Args: cache.SetBytesArgs{
						Key:   "configblob::docker.io/library/alpine:3.10",
						Value: []byte(`foo`),
					},
					Returns: cache.SetBytesReturns{Err: nil},
				},
			},
			configBlob: []ConfigBlobExpectation{
				{
					Args: ConfigBlobArgs{
						CtxAnything: true,
					},
					Returns: ConfigBlobReturns{
						Blob: []byte(`foo`),
					},
				},
			},
			want: []byte(`foo`),
		},
		{
			name: "happy path with cache",
			fields: fields{
				name:   "docker.io/library/alpine:3.11",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "configblob::docker.io/library/alpine:3.11",
					},
					Returns: cache.GetReturns{Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`)))},
				},
			},
			want: []byte(`foo`),
		},
		{
			name: "happy path: cache.SetBytes returns an error, but it is ignored",
			fields: fields{
				name:   "docker.io/library/alpine:3.11",
				isFile: false,
			},
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "configblob::docker.io/library/alpine:3.11",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSetBytes: []cache.SetBytesExpectation{
				{
					Args: cache.SetBytesArgs{
						Key:           "configblob::docker.io/library/alpine:3.11",
						ValueAnything: true,
					},
					Returns: cache.SetBytesReturns{Err: xerrors.New("error")},
				},
			},
			configBlob: []ConfigBlobExpectation{
				{
					Args: ConfigBlobArgs{
						CtxAnything: true,
					},
					Returns: ConfigBlobReturns{
						Blob: []byte(`bar`),
					},
				},
			},
			want: []byte(`bar`),
		},
		{
			name: "happy path: tar file",
			fields: fields{
				name:   "/workspace/alpine-3.10.tar",
				isFile: true,
			},
			configBlob: []ConfigBlobExpectation{
				{
					Args: ConfigBlobArgs{
						CtxAnything: true,
					},
					Returns: ConfigBlobReturns{
						Blob: []byte(`baz`),
					},
				},
			},
			want: []byte(`baz`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockCache)
			c.ApplyGetExpectations(tt.cacheGet)
			c.ApplySetBytesExpectations(tt.cacheSetBytes)

			rawSource := new(MockImageSource)

			src := new(MockImageCloser)
			src.ApplyConfigBlobExpectations(tt.configBlob)

			img := &Image{
				name:      tt.fields.name,
				isFile:    tt.fields.isFile,
				rawSource: rawSource,
				src:       src,
				cache:     c,
			}
			got, err := img.ConfigBlob(context.Background())
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}

			assert.Equal(t, tt.want, got, tt.name)

			c.AssertExpectations(t)
			rawSource.AssertExpectations(t)
			src.AssertExpectations(t)
		})
	}
}

func TestImage_GetBlob(t *testing.T) {
	tests := []struct {
		name     string
		dig      digest.Digest
		cacheGet []cache.GetExpectation
		cacheSet []cache.SetExpectation
		getBlob  []GetBlobExpectation
		want     []byte
		wantErr  string
	}{
		{
			name: "happy path without cache",
			dig:  "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSet: []cache.SetExpectation{
				{
					Args: cache.SetArgs{
						Key:          "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
						FileAnything: true,
					},
					Returns: cache.SetReturns{
						Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`))),
					},
				},
			},
			getBlob: []GetBlobExpectation{
				{
					Args: GetBlobArgs{
						CtxAnything: true,
						Info: imageTypes.BlobInfo{
							Digest: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
							Size:   -1,
						},
						CacheAnything: true,
					},
					Returns: GetBlobReturns{
						Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`))),
					},
				},
			},
			want: []byte(`foo`),
		},
		{
			name: "happy path with cache",
			dig:  "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "sha256:03901b4a2ea88eeaad62dbe59b072b28b6efa00491962b8741081c5df50c65e0",
					},
					Returns: cache.GetReturns{
						Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`))),
					},
				},
			},
			want: []byte(`foo`),
		},
		{
			name: "sad path without cache, GetBlob returns an error",
			dig:  "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
			cacheGet: []cache.GetExpectation{
				{
					Args: cache.GetArgs{
						Key: "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
					},
					Returns: cache.GetReturns{Reader: nil},
				},
			},
			cacheSet: []cache.SetExpectation{
				{
					Args: cache.SetArgs{
						Key:          "sha256:e6b0cf9c0882fb079c9d35361d12ff4691f916b6d825061247d1bd0b26d7cf3f",
						FileAnything: true,
					},
					Returns: cache.SetReturns{
						Reader: ioutil.NopCloser(bytes.NewBuffer([]byte(`foo`))),
					},
				},
			},
			getBlob: []GetBlobExpectation{
				{
					Args: GetBlobArgs{
						CtxAnything:   true,
						InfoAnything:  true,
						CacheAnything: true,
					},
					Returns: GetBlobReturns{
						Err: errors.New("get blob failed error"),
					},
				},
			},
			wantErr: "get blob failed error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(cache.MockCache)
			c.ApplyGetExpectations(tt.cacheGet)
			c.ApplySetExpectations(tt.cacheSet)

			rawSource := new(MockImageSource)
			rawSource.ApplyGetBlobExpectations(tt.getBlob)

			src := new(MockImageCloser)

			img := &Image{
				name:      "dummy",
				isFile:    false,
				rawSource: rawSource,
				src:       src,
				cache:     c,
			}
			r, cleanup, err := img.GetBlob(context.Background(), tt.dig)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				require.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			} else {
				require.NoError(t, err, tt.name)
			}
			defer cleanup()

			got, err := ioutil.ReadAll(r)
			require.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got, tt.name)

			c.AssertExpectations(t)
			rawSource.AssertExpectations(t)
			src.AssertExpectations(t)
		})
	}
}
