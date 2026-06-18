package keystore

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/hashicorp/vault/api"
)

type AwsS3Keystore struct {
	encryptionKey    string
	encryptionKeyMD5 string
	bucketName       string
	bucketPath       string
	s3Service        *s3.S3
}

type AwsS3KeystoreConfig struct {
	AwsConfig     *AwsConfig
	EncryptionKey string
	BucketName    string
	BucketPath    string
}

func NewAwsS3Keystore(config *AwsS3KeystoreConfig) (*AwsS3Keystore, error) {
	awsSession, err := waitUntilValidSession(config.AwsConfig)
	if err != nil {
		return nil, err
	}
	
	s3Service := s3.New(awsSession)

	md5Sum := md5.Sum([]byte(config.EncryptionKey))
	encryptionKeyMD5 := base64.StdEncoding.EncodeToString(md5Sum[:])

	return &AwsS3Keystore{
		encryptionKey:    config.EncryptionKey,
		encryptionKeyMD5: encryptionKeyMD5,
		bucketName:       config.BucketName,
		bucketPath:       config.BucketPath,
		s3Service:        s3Service,
	}, nil
}

func (keystore *AwsS3Keystore) getBucketPath(name string) string {
	return path.Join(strings.TrimRight(keystore.bucketPath, "/"), name)
}

func (keystore *AwsS3Keystore) Close() {
	// nothing to close
}

func (keystore *AwsS3Keystore) EncryptAndWrite(initResponse *api.InitResponse) error {
	// Save only the threshold number of unseal keys (no root token)
	unsealData := UnsealData{
		Keys:    initResponse.Keys[:3],
		KeysB64: initResponse.KeysB64[:3],
	}
	initResponseData, err := json.Marshal(&unsealData)
	if err != nil {
		return err
	}
	err = keystore.s3Put(keystore.getBucketPath(unsealKeysFile), bytes.NewReader(initResponseData))
	if err != nil {
		return err
	}

	// Save the root token separately
	rootTokenData, err := json.Marshal(&initResponse.RootToken)
	if err != nil {
		return err
	}
	err = keystore.s3Put(keystore.getBucketPath(rootTokenFile), bytes.NewReader(rootTokenData))
	if err != nil {
		return err
	}

	return nil
}

func (keystore *AwsS3Keystore) ReadAndDecrypt() (*api.InitResponse, error) {
	getObjectInput := s3.GetObjectInput{
		Bucket:               &keystore.bucketName,
		Key:                  aws.String(keystore.getBucketPath(unsealKeysFile)),
		SSECustomerKey:       &keystore.encryptionKey,
		SSECustomerKeyMD5:    &keystore.encryptionKeyMD5,
		SSECustomerAlgorithm: aws.String(s3.ServerSideEncryptionAes256),
	}
	getObjectOutput, err := keystore.s3Service.GetObjectWithContext(context.Background(), &getObjectInput)
	if err != nil {
		return nil, err
	}

	var initResponse api.InitResponse

	err = json.NewDecoder(getObjectOutput.Body).Decode(&initResponse)
	if err != nil {
		return nil, err
	}
	return &initResponse, nil
}

func (keystore *AwsS3Keystore) s3Put(name string, body io.ReadSeeker) error {
	putObjectInput := s3.PutObjectInput{
		Bucket:               &keystore.bucketName,
		Key:                  &name,
		Body:                 body,
		SSECustomerKey:       &keystore.encryptionKey,
		SSECustomerKeyMD5:    &keystore.encryptionKeyMD5,
		SSECustomerAlgorithm: aws.String(s3.ServerSideEncryptionAes256),
	}

	_, err := keystore.s3Service.PutObjectWithContext(context.Background(), &putObjectInput)
	if err != nil {
		return err
	}

	return nil
}
