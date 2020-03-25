package image

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/fanal/testutils"

	"github.com/aquasecurity/fanal/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestNewDockerImage(t *testing.T) {
	filePaths := map[string]string{
		"index.docker.io/library/alpine:3.11": "testdata/alpine-310.tar.gz",
	}
	te := testutils.NewDockerEngine("1.38", filePaths)
	defer te.Close()

	filePaths = map[string]string{
		"library/alpine:3.11": "testdata/alpine-310.tar.gz",
	}
	tr := testutils.NewDockerRegistry(filePaths)
	defer tr.Close()

	//pp.Println(ts.Listener.Addr().String())
	os.Setenv("DOCKER_HOST", fmt.Sprintf("tcp://%s", te.Listener.Addr().String()))

	type args struct {
		imageName string
		option    types.DockerOption
	}
	tests := []struct {
		name    string
		args    args
		want    v1.Image
		wantErr bool
	}{
		{
			name: "happy path with Docker Engine",
			args: args{
				imageName: "alpine:3.11",
			},
		},
		{
			name: "happy path with Docker Registry",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.11", tr.Listener.Addr().String()),
			},
		},
		{
			name: "happy path with insecure Docker Registry",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.11", tr.Listener.Addr().String()),
				option: types.DockerOption{
					UserName:              "test",
					Password:              "test",
					NonSSL:                true,
					InsecureSkipTLSVerify: true,
				},
			},
		},
		{
			name: "sad path with invalid tag",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:3.11!!!", tr.Listener.Addr().String()),
			},
			wantErr: true,
		},
		{
			name: "sad path with non-exist image",
			args: args{
				imageName: fmt.Sprintf("%s/library/alpine:100", tr.Listener.Addr().String()),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println(os.Getenv("DOCKER_HOST"))
			_, err := NewDockerImage(context.Background(), tt.args.imageName, tt.args.option)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDockerImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewDockerArchiveImage(t *testing.T) {
	type args struct {
		fileName string
	}
	tests := []struct {
		name    string
		args    args
		want    v1.Image
		wantErr bool
	}{
		{
			name: "happy path",
			args: args{
				fileName: "testdata/alpine-310.tar.gz",
			},
		},
		{
			name: "sad path",
			args: args{
				fileName: "testdata/invalid.tar.gz",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDockerArchiveImage(tt.args.fileName)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDockerArchiveImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
