package image

import (
	"context"
	"testing"

	imageTypes "github.com/containers/image/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
				DockerAuthConfig:                  &imageTypes.DockerAuthConfig{},
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
				DockerAuthConfig:            &imageTypes.DockerAuthConfig{},
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
				DockerAuthConfig:            &imageTypes.DockerAuthConfig{},
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
				DockerAuthConfig:            &imageTypes.DockerAuthConfig{},
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
				DockerAuthConfig:            &imageTypes.DockerAuthConfig{},
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
