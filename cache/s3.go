package cache

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
)

var _ Cache = &S3Cache{}

type S3Cache struct {
	s3Client   s3iface.S3API
	downloader s3manageriface.DownloaderAPI
	bucketName string
	prefix     string
}

func NewS3Cache(bucketName, prefix string, api s3iface.S3API, downloaderAPI s3manageriface.DownloaderAPI) (S3Cache, error) {
	return S3Cache{
		s3Client:   api,
		downloader: downloaderAPI,
		bucketName: bucketName,
		prefix:     prefix,
	}, nil
}

func (c S3Cache) PutArtifact(artifactID string, artifactConfig types.ArtifactInfo) (err error) {
	key := fmt.Sprintf("%s/%s/%s", artifactBucket, c.prefix, artifactID)
	if err := c.put(key, artifactConfig); err != nil {
		return xerrors.Errorf("unable to store artifact information in cache (%s): %w", artifactID, err)
	}
	return nil
}

func (c S3Cache) PutBlob(blobID string, blobInfo types.BlobInfo) error {
	if _, err := v1.NewHash(blobID); err != nil {
		return xerrors.Errorf("invalid diffID (%s): %w", blobID, err)
	}
	key := fmt.Sprintf("%s/%s/%s", blobBucket, c.prefix, blobID)
	if err := c.put(key, blobInfo); err != nil {
		return xerrors.Errorf("unable to store blob information in cache (%s): %w", blobID, err)
	}
	return nil
}

func (c S3Cache) put(key string, body interface{}) (err error) {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	params := &s3.PutObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(key),
		Body:   bytes.NewReader(b),
	}
	_, err = c.s3Client.PutObject(params)
	if err != nil {
		return xerrors.Errorf("unable to put object: %w", err)
	}
	headObjectInput := &s3.HeadObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(key),
	}
	if err = c.s3Client.WaitUntilObjectExists(headObjectInput); err != nil {
		return xerrors.Errorf("information was not found in cache: %w", err)
	}
	return nil
}

func (c S3Cache) GetBlob(blobID string) (types.BlobInfo, error) {
	var blobInfo types.BlobInfo
	buf := aws.NewWriteAtBuffer([]byte{})
	_, err := c.downloader.Download(buf, &s3.GetObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(fmt.Sprintf("%s/%s/%s", blobBucket, c.prefix, blobID)),
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("failed to get blob from the cache: %w", err)
	}
	err = json.Unmarshal(buf.Bytes(), &blobInfo)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}

	return blobInfo, nil
}

func (c S3Cache) GetArtifact(artifactID string) (types.ArtifactInfo, error) {
	var info types.ArtifactInfo

	buf := aws.NewWriteAtBuffer([]byte{})
	_, err := c.downloader.Download(buf, &s3.GetObjectInput{
		Bucket: aws.String(c.bucketName),
		Key:    aws.String(fmt.Sprintf("%s/%s/%s", artifactBucket, c.prefix, artifactID)),
	})
	if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("failed to get artifact from the cache: %w", err)
	}
	err = json.Unmarshal(buf.Bytes(), &info)
	if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}

	return info, nil
}

func (c S3Cache) MissingBlobs(artifactID string, blobIDs []string) (bool, []string, error) {
	var missingArtifact bool
	var missingBlobIDs []string
	for _, blobID := range blobIDs {
		blobInfo, err := c.GetBlob(blobID)
		if err != nil {
			// error means cache missed blob info
			missingBlobIDs = append(missingBlobIDs, blobID)
			continue
		}
		if blobInfo.SchemaVersion != types.BlobJSONSchemaVersion {
			missingBlobIDs = append(missingBlobIDs, blobID)
		}
	}
	// get artifact info
	artifactInfo, err := c.GetArtifact(artifactID)
	if err != nil {
		// error means cache missed artifact info
		return true, missingBlobIDs, nil
	}
	if artifactInfo.SchemaVersion != types.ArtifactJSONSchemaVersion {
		missingArtifact = true
	}

	return missingArtifact, missingBlobIDs, nil
}

func (c S3Cache) Close() error {
	return nil
}

func (c S3Cache) Clear() error {
	return nil
}
