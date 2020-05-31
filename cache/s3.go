package cache

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/fanal/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"
)

type S3Cache struct {
	s3         s3iface.S3API
	downloader *s3manager.Downloader
	bucketName string
}

func NewS3Cache(region string, bucketName string) (S3Cache, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Region: aws.String(region)},
	})
	if err != nil {
		return S3Cache{}, xerrors.Errorf("failed to load aws credentials: %w", err)
	}

	return S3Cache{
		s3:         s3.New(sess, aws.NewConfig().WithRegion(region)),
		downloader: s3manager.NewDownloader(sess),
		bucketName: bucketName,
	}, nil
}

func (cache S3Cache) PutLayer(diffID string, layerInfo types.BlobInfo, opts ...Option) error {
	options := initOpts(opts)
	if _, err := v1.NewHash(diffID); err != nil {
		return xerrors.Errorf("invalid diffID (%s): %w", diffID, err)
	}
	key := fmt.Sprintf("%s/%s/%s", blobBucket, options.S3Prefix, diffID)
	if err := cache.put(key, layerInfo); err != nil {
		return xerrors.Errorf("unable to store layer information in cache (%s): %w", diffID, err)
	}
	return nil
}

func (cache S3Cache) PutImage(imageID string, imageConfig types.ArtifactInfo, opts ...Option) (err error) {
	options := initOpts(opts)
	key := fmt.Sprintf("%s/%s/%s", artifactBucket, options.S3Prefix, imageID)
	if err := cache.put(key, imageConfig); err != nil {
		return xerrors.Errorf("unable to store image information in cache (%s): %w", imageID, err)
	}
	return nil
}

func (cache S3Cache) put(key string, body interface{}) (err error) {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	params := &s3.PutObjectInput{
		Bucket: aws.String(cache.bucketName),
		Key:    aws.String(key),
		Body:   bytes.NewReader(b),
	}
	_, err = cache.s3.PutObject(params)
	if err != nil {
		return xerrors.Errorf("unable to put object: %w", err)
	}
	headObjectInput := &s3.HeadObjectInput{
		Bucket: aws.String(cache.bucketName),
		Key:    aws.String(key),
	}
	if err = cache.s3.WaitUntilObjectExists(headObjectInput); err != nil {
		return xerrors.Errorf("information was not found in cache: %w", err)
	}
	return nil
}

func (cache S3Cache) GetLayer(diffID string, opts ...Option) (types.BlobInfo, error) {
	var layerInfo types.BlobInfo

	options := initOpts(opts)
	buf := aws.NewWriteAtBuffer([]byte{})
	_, err := cache.downloader.Download(buf, &s3.GetObjectInput{
		Bucket: aws.String(cache.bucketName),
		Key:    aws.String(fmt.Sprintf("%s/%s/%s", blobBucket, options.S3Prefix, diffID)),
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("failed to get layer from the cache: %w", err)
	}
	err = json.Unmarshal(buf.Bytes(), &layerInfo)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}

	return layerInfo, nil
}

func (cache S3Cache) GetImage(imageID string, opts ...Option) (types.ArtifactInfo, error) {
	var info types.ArtifactInfo

	options := initOpts(opts)
	buf := aws.NewWriteAtBuffer([]byte{})
	_, err := cache.downloader.Download(buf, &s3.GetObjectInput{
		Bucket: aws.String(cache.bucketName),
		Key:    aws.String(fmt.Sprintf("%s/%s/%s", artifactBucket, options.S3Prefix, imageID)),
	})
	if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("failed to get image from the cache: %w", err)
	}
	err = json.Unmarshal(buf.Bytes(), &info)
	if err != nil {
		return types.ArtifactInfo{}, xerrors.Errorf("JSON unmarshal error: %w", err)
	}

	return info, nil
}

func (cache S3Cache) MissingLayers(imageID string, layerIDs []string, opts ...Option) (bool, []string, error) {
	var missingImage bool
	var missingLayerIDs []string
	for _, layerID := range layerIDs {
		layerInfo, err := cache.GetLayer(layerID, opts...)
		if err != nil {
			// error means cache missed layer info
			missingLayerIDs = append(missingLayerIDs, layerID)
			continue
		}
		if layerInfo.SchemaVersion != types.BlobJSONSchemaVersion {
			missingLayerIDs = append(missingLayerIDs, layerID)
		}
	}
	// get image info
	imageInfo, err := cache.GetImage(imageID, opts...)
	if err != nil {
		// error means cache missed image info
		return true, missingLayerIDs, nil
	}
	if imageInfo.SchemaVersion != types.ArtifactJSONSchemaVersion {
		missingImage = true
	}

	return missingImage, missingLayerIDs, nil
}

func (cache S3Cache) Close() error {
	return nil
}

func (cache S3Cache) Clear() error {
	return nil
}
