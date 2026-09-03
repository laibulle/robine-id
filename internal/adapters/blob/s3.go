package blob

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

type S3 struct {
	Client S3API
	Bucket string
	Prefix string
}

func (s S3) key(key string) (string, error) {
	key = strings.TrimPrefix(key, "/")
	if key == "" || strings.Contains(key, "../") || strings.HasPrefix(key, "..") {
		return "", fmt.Errorf("invalid blob key")
	}
	return strings.Trim(strings.Trim(s.Prefix, "/")+"/"+key, "/"), nil
}

func (s S3) Read(ctx context.Context, key string) ([]byte, error) {
	objectKey, err := s.key(key)
	if err != nil {
		return nil, err
	}
	output, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(objectKey)})
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()
	return io.ReadAll(output.Body)
}

// An S3 PutObject replaces an object atomically from a reader's perspective.
func (s S3) WriteAtomic(ctx context.Context, key string, data []byte, _ fs.FileMode) error {
	objectKey, err := s.key(key)
	if err != nil {
		return err
	}
	_, err = s.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(objectKey), Body: bytes.NewReader(data)})
	return err
}

func (s S3) List(ctx context.Context, prefix string) ([]string, error) {
	objectPrefix, err := s.key(prefix)
	if err != nil {
		return nil, err
	}
	var keys []string
	var token *string
	for {
		output, err := s.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(s.Bucket), Prefix: aws.String(objectPrefix), ContinuationToken: token})
		if err != nil {
			return nil, err
		}
		base := strings.Trim(strings.Trim(s.Prefix, "/")+"/", "/")
		if base != "" {
			base += "/"
		}
		for _, object := range output.Contents {
			keys = append(keys, strings.TrimPrefix(aws.ToString(object.Key), base))
		}
		if !aws.ToBool(output.IsTruncated) {
			break
		}
		token = output.NextContinuationToken
	}
	sort.Strings(keys)
	return keys, nil
}
