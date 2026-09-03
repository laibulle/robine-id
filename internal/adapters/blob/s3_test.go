package blob

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type fakeS3 struct {
	objects map[string][]byte
	pages   int
}

func (f *fakeS3) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(f.objects[aws.ToString(input.Key)]))}, nil
}
func (f *fakeS3) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	data, _ := io.ReadAll(input.Body)
	f.objects[aws.ToString(input.Key)] = data
	return &s3.PutObjectOutput{}, nil
}
func (f *fakeS3) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.pages++
	if input.ContinuationToken == nil {
		return &s3.ListObjectsV2Output{Contents: []types.Object{{Key: aws.String("root/apps/b.json")}}, IsTruncated: aws.Bool(true), NextContinuationToken: aws.String("next")}, nil
	}
	return &s3.ListObjectsV2Output{Contents: []types.Object{{Key: aws.String("root/apps/a.json")}}}, nil
}

func TestS3RoundTripAndPaginatedList(t *testing.T) {
	ctx := context.Background()
	api := &fakeS3{objects: map[string][]byte{}}
	store := S3{Client: api, Bucket: "bucket", Prefix: "root"}
	if err := store.WriteAtomic(ctx, "config.json", []byte("hello"), 0); err != nil {
		t.Fatal(err)
	}
	data, err := store.Read(ctx, "config.json")
	if err != nil || string(data) != "hello" {
		t.Fatalf("read %s %v", data, err)
	}
	keys, err := store.List(ctx, "apps")
	if err != nil || !reflect.DeepEqual(keys, []string{"apps/a.json", "apps/b.json"}) || api.pages != 2 {
		t.Fatalf("list %#v %v", keys, err)
	}
	for _, key := range []string{"", "../bad"} {
		if store.WriteAtomic(ctx, key, nil, 0) == nil {
			t.Errorf("accepted %q", key)
		}
	}
}
