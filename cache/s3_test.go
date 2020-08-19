package cache

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"

	"github.com/aquasecurity/fanal/types"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type mockS3Client struct {
	s3iface.S3API
}

func (m *mockS3Client) PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) HeadObject(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return &s3.HeadObjectOutput{}, nil
}

func TestS3Cache_PutBlob(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
		Prefix     string
	}
	type args struct {
		blobID   string
		blobInfo types.BlobInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				blobID: "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7",
				blobInfo: types.BlobInfo{
					Version: 1,
					OS: &types.OS{
						Family: "alpine",
						Name:   "3.10",
					},
				}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			if err := c.PutBlob(tt.args.blobID, tt.args.blobInfo); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.PutBlob() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3Cache_PutArtifact(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
		Prefix     string
	}
	type args struct {
		artifactID     string
		artifactConfig types.ArtifactInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				artifactID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				artifactConfig: types.ArtifactInfo{
					Version:       1,
					Architecture:  "amd64",
					Created:       time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
					DockerVersion: "18.06.1-ce",
					OS:            "linux",
					HistoryPackages: []types.Package{
						{
							Name:    "musl",
							Version: "1.2.3",
						},
					},
				}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			if err := c.PutArtifact(tt.args.artifactID, tt.args.artifactConfig); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.PutArtifact() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3Cache_getIndex(t *testing.T) {
	mockSvc := &mockS3Client{}

	type fields struct {
		S3         s3iface.S3API
		Downloader *s3manager.Downloader
		BucketName string
		Prefix     string
	}
	type args struct {
		key     string
		keyType string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				S3:         mockSvc,
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				key:     "key",
				keyType: "artifactBucket",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			if err := c.getIndex(tt.args.key, tt.args.keyType); (err != nil) != tt.wantErr {
				t.Errorf("S3Cache.getIndex() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type mockS3ClientMissingBlobs struct {
	s3iface.S3API
	headObjectFunc func(*s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
}

func (m *mockS3ClientMissingBlobs) PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3ClientMissingBlobs) HeadObject(hio *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	if m.headObjectFunc != nil {
		return m.headObjectFunc(hio)
	}

	return &s3.HeadObjectOutput{}, nil
}

type mockS3Downloader struct {
	s3manageriface.DownloaderAPI
	download func(io.WriterAt, *s3.GetObjectInput, ...func(*s3manager.Downloader)) (int64, error)
}

func (m *mockS3Downloader) Download(w io.WriterAt, input *s3.GetObjectInput, downloadFunc ...func(*s3manager.Downloader)) (int64, error) {
	if m.download != nil {
		return m.download(w, input, downloadFunc...)
	}

	return 0, nil
}

func TestS3Cache_MissingBlobs(t *testing.T) {
	type fields struct {
		S3         s3iface.S3API
		Downloader s3manageriface.DownloaderAPI
		BucketName string
		Prefix     string
	}
	type args struct {
		artifactID string
		blobIDs    []string
	}
	tests := []struct {
		name                 string
		fields               fields
		args                 args
		want                 bool
		wantMissingBlobSlice []string
		wantErr              string
	}{
		{
			name: "happy path, with missing blob, with missing artifact",
			fields: fields{
				S3: &mockS3ClientMissingBlobs{
					headObjectFunc: func(input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
						return &s3.HeadObjectOutput{}, xerrors.Errorf("the object doesn't exist in S3")
					},
				},
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				artifactID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				blobIDs:    []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
			},
			want:                 true,
			wantMissingBlobSlice: []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
		},
		{
			name: "happy path, blob schema mismatch",
			fields: fields{
				S3: &mockS3ClientMissingBlobs{
					headObjectFunc: func(input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
						if strings.Contains(*input.Key, "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7") {
							return &s3.HeadObjectOutput{}, xerrors.Errorf("the object doesn't exist in S3")
						}

						return &s3.HeadObjectOutput{}, nil
					},
				},
				Downloader: &mockS3Downloader{download: func(at io.WriterAt, input *s3.GetObjectInput, f ...func(*s3manager.Downloader)) (int64, error) {
					// blob
					if strings.Contains(*input.Key, "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7") {
						at.WriteAt([]byte(`{
							"Version": 666,
							"Digest": "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"
						}`), 0)
						return 0, nil
					}

					// artifact
					if strings.Contains(*input.Key, "58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4") {
						at.WriteAt([]byte(`{
							"Version": 1
						}`), 0)
						return 0, nil
					}

					return 0, nil
				}},
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				artifactID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				blobIDs:    []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
			},
			want:                 false,
			wantMissingBlobSlice: []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
		},
		{
			name: "happy path, artifact schema mismatch",
			fields: fields{
				S3: &mockS3ClientMissingBlobs{
					headObjectFunc: func(input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
						if strings.Contains(*input.Key, "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7") {
							return &s3.HeadObjectOutput{}, xerrors.Errorf("the object doesn't exist in S3")
						}

						return &s3.HeadObjectOutput{}, nil
					},
				},
				Downloader: &mockS3Downloader{download: func(at io.WriterAt, input *s3.GetObjectInput, f ...func(*s3manager.Downloader)) (int64, error) {
					// blob
					if strings.Contains(*input.Key, "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7") {
						at.WriteAt([]byte(`{
							"Version": 1,
							"Digest": "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"
						}`), 0)
						return 0, nil
					}

					// artifact
					if strings.Contains(*input.Key, "58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4") {
						at.WriteAt([]byte(`{
							"Version": 666
						}`), 0)
						return 0, nil
					}

					return 0, nil
				}},
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				artifactID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				blobIDs:    []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
			},
			want:                 true,
			wantMissingBlobSlice: []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
		},
		{
			name: "sad path, with missing blob, with present artifact",
			fields: fields{
				S3: &mockS3ClientMissingBlobs{
					headObjectFunc: func(input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
						// error if blob
						if strings.Contains(*input.Key, "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7") {
							return &s3.HeadObjectOutput{}, xerrors.Errorf("the object doesn't exist in S3")
						}

						// ok if artifact
						return &s3.HeadObjectOutput{}, nil
					},
				},
				Downloader: &mockS3Downloader{download: func(at io.WriterAt, input *s3.GetObjectInput, f ...func(*s3manager.Downloader)) (int64, error) {
					return -1, errors.New("download failed")
				}},
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				artifactID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				blobIDs:    []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
			},
			want:                 true,
			wantMissingBlobSlice: []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
			wantErr:              "the artifact object (sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4) doesn't exist in S3 even though the index file exists",
		},
		{
			name: "sad path, blob download failure",
			fields: fields{
				S3: &mockS3ClientMissingBlobs{
					headObjectFunc: func(input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
						if strings.Contains(*input.Key, "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7") {
							return &s3.HeadObjectOutput{}, xerrors.Errorf("the object doesn't exist in S3")
						}

						return &s3.HeadObjectOutput{}, nil
					},
				},
				Downloader: &mockS3Downloader{download: func(at io.WriterAt, input *s3.GetObjectInput, f ...func(*s3manager.Downloader)) (int64, error) {
					if strings.Contains(*input.Key, "24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7") {
						at.WriteAt([]byte(`{
							"Version": 1,
							"Digest": "sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"
						}`), 0)
						return 0, nil
					}
					return -1, errors.New("download failed")
				}},
				BucketName: "test",
				Prefix:     "prefix",
			},
			args: args{
				artifactID: "sha256:58701fd185bda36cab0557bb6438661831267aa4a9e0b54211c4d5317a48aff4",
				blobIDs:    []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7", "sha256:ffffff4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
			},
			want:                 true,
			wantMissingBlobSlice: []string{"sha256:24df0d4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7"},
			wantErr:              "the blob object (sha256:ffffff4e20c0f42d3703bf1f1db2bdd77346c7956f74f423603d651e8e5ae8a7) doesn't exist in S3 even though the index file exists",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewS3Cache(tt.fields.BucketName, tt.fields.Prefix, tt.fields.S3, tt.fields.Downloader)
			gotBool, gotSlice, err := c.MissingBlobs(tt.args.artifactID, tt.args.blobIDs)
			switch {
			case tt.wantErr != "":
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, gotBool, tt.name)
			assert.Equal(t, tt.wantMissingBlobSlice, gotSlice, tt.name)
		})
	}
}
