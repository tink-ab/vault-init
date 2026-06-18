package keystore

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/hashicorp/vault/api"
)

type AwsKeystore struct {
	kmsKeyID          string
	secretsPath       string
	secretsMgrService *secretsmanager.SecretsManager
}

type AwsKeystoreConfig struct {
	AwsConfig   *AwsConfig
	KmsKeyID    string
	SecretsPath string
}

type AwsConfig struct {
	Endpoint                string
	RetryOnCredentialsWait  time.Duration
}

func createAwsSession(config *AwsConfig) *session.Session {
	if config.Endpoint != "" {
		if !isLoopbackEndpoint(config.Endpoint) {
			log.Fatalf("AWS_ENDPOINT must be a loopback address (localhost/127.0.0.1) for local testing only, got: %s", config.Endpoint)
		}
		return session.Must(session.NewSession(&aws.Config{
			Endpoint:         &config.Endpoint,
			S3ForcePathStyle: aws.Bool(true),
		}))
	}

	return session.Must(session.NewSession())
}

func isLoopbackEndpoint(endpoint string) bool {
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")
	host := strings.Split(endpoint, ":")[0]
	host = strings.Split(host, "/")[0]
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func waitUntilValidSession(config *AwsConfig) (*session.Session, error) {
	awsSession := createAwsSession(config)
	for {
		_, err := awsSession.Config.Credentials.Get()
		if err != credentials.ErrNoValidProvidersFoundInChain {
			return awsSession, err
		}

		_, _ = fmt.Fprintf(os.Stderr, "[ERROR] Failed get retrieve AWS credentials. Retrying.. %v", err)
		awsSession = createAwsSession(config)
		time.Sleep(config.RetryOnCredentialsWait)
	}
}

func NewAwsKeystore(config *AwsKeystoreConfig) (*AwsKeystore, error) {
	awsSession, err := waitUntilValidSession(config.AwsConfig)
	if err != nil {
		return nil, err
	}

	secretsMgrService := secretsmanager.New(awsSession)

	return &AwsKeystore{
		kmsKeyID:          config.KmsKeyID,
		secretsPath:       config.SecretsPath,
		secretsMgrService: secretsMgrService,
	}, nil
}

func (keystore *AwsKeystore) secretPath(name string) string {
	return path.Join(strings.TrimRight(keystore.secretsPath, "/"), name)
}

func (keystore AwsKeystore) Close() {
	// nothing to close
}

func (keystore AwsKeystore) EncryptAndWrite(initResponse *api.InitResponse) error {
	// Save only the threshold number of unseal keys (no root token)
	unsealData := UnsealData{
		Keys:    initResponse.Keys[:3],
		KeysB64: initResponse.KeysB64[:3],
	}
	initResponseData, err := json.Marshal(&unsealData)
	if err != nil {
		return err
	}
	err = keystore.createSecret(unsealKeysFile, initResponseData)
	if err != nil {
		return err
	}

	// Save the root token separately
	rootTokenData, err := json.Marshal(&initResponse.RootToken)
	if err != nil {
		return err
	}
	err = keystore.createSecret(rootTokenFile, rootTokenData)
	if err != nil {
		return err
	}

	return nil
}

func (keystore AwsKeystore) ReadAndDecrypt() (*api.InitResponse, error) {
	secretPath := keystore.secretPath(unsealKeysFile)
	secretValueInput := secretsmanager.GetSecretValueInput{
		SecretId: &secretPath,
	}
	secretValueOutput, err := keystore.secretsMgrService.GetSecretValueWithContext(context.Background(), &secretValueInput)
	if err != nil {
		return nil, err
	}

	var initResponse api.InitResponse

	err = json.Unmarshal(secretValueOutput.SecretBinary, &initResponse)
	if err != nil {
		return nil, err
	}
	return &initResponse, nil
}

func (keystore AwsKeystore) createSecret(name string, content []byte) error {
	secretPath := keystore.secretPath(name)
	secretInput := secretsmanager.CreateSecretInput{
		KmsKeyId:     &keystore.kmsKeyID,
		Name:         &secretPath,
		SecretBinary: content,
	}

	_, err := keystore.secretsMgrService.CreateSecretWithContext(context.Background(), &secretInput)
	if err != nil {
		return err
	}

	log.Printf("Secret written to secretsmanager as '%s'", secretPath)
	return nil
}
