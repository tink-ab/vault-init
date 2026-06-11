package keystore

import (
	"cloud.google.com/go/storage"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/hashicorp/vault/api"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
	"io/ioutil"
	"log"
)

type GcpKeystore struct {
	gcsBucketName    string
	kmsKeyID         string
	kmsService       *cloudkms.Service
	kmsCtxCancel     context.CancelFunc
	storageClient    *storage.Client
	storageCtxCancel context.CancelFunc
}

func NewGcpKeystore(gcsBucketName string, kmsKeyID string) (*GcpKeystore, error) {
	kmsCtx, kmsCtxCancel := context.WithCancel(context.Background())
	kmsClient, err := google.DefaultClient(kmsCtx, "https://www.googleapis.com/auth/cloudkms")
	if err != nil {
		return nil, err
	}

	kmsService, err := cloudkms.New(kmsClient)
	if err != nil {
		return nil, err
	}

	kmsService.UserAgent = UserAgent
	storageCtx, storageCtxCancel := context.WithCancel(context.Background())

	storageClient, err := storage.NewClient(storageCtx,
		option.WithUserAgent(UserAgent),
		option.WithScopes(storage.ScopeReadWrite),
	)
	if err != nil {
		storageCtxCancel()
		return nil, err
	}

	return &GcpKeystore{
		gcsBucketName:    gcsBucketName,
		kmsKeyID:         kmsKeyID,
		kmsService:       kmsService,
		kmsCtxCancel:     kmsCtxCancel,
		storageClient:    storageClient,
		storageCtxCancel: storageCtxCancel,
	}, nil
}

func (keystore GcpKeystore) Close() {
	defer keystore.kmsCtxCancel()
	defer keystore.storageCtxCancel()
}

func (keystore GcpKeystore) EncryptAndWrite(initResponse *api.InitResponse) error {
	rootTokenEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte(initResponse.RootToken)),
	}

	rootTokenEncryptResponse, err := keystore.kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(keystore.kmsKeyID, rootTokenEncryptRequest).Do()
	if err != nil {
		return err
	}

	// Store only the threshold number of unseal keys (no root token)
	unsealData := UnsealData{
		Keys:    initResponse.Keys[:3],
		KeysB64: initResponse.KeysB64[:3],
	}
	initResponseData, err := json.Marshal(&unsealData)
	if err != nil {
		return err
	}

	unsealKeysEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(initResponseData),
	}

	unsealKeysEncryptResponse, err := keystore.kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(keystore.kmsKeyID, unsealKeysEncryptRequest).Do()
	if err != nil {
		return err
	}

	bucket := keystore.storageClient.Bucket(keystore.gcsBucketName)

	// Save the encrypted unseal keys.
	ctx := context.Background()
	unsealKeysObject := bucket.Object("unseal-keys.json.enc").NewWriter(ctx)

	_, err = unsealKeysObject.Write([]byte(unsealKeysEncryptResponse.Ciphertext))
	if err != nil {
		unsealKeysObject.Close()
		return err
	}

	if err = unsealKeysObject.Close(); err != nil {
		return err
	}

	log.Printf("Unseal keys written to gs://%s/%s", keystore.gcsBucketName, "unseal-keys.json.enc")

	// Save the encrypted root token.
	rootTokenObject := bucket.Object("root-token.enc").NewWriter(ctx)

	_, err = rootTokenObject.Write([]byte(rootTokenEncryptResponse.Ciphertext))
	if err != nil {
		rootTokenObject.Close()
		return err
	}

	if err = rootTokenObject.Close(); err != nil {
		return err
	}

	log.Printf("Root token written to gs://%s/%s", keystore.gcsBucketName, "root-token.enc")
	return nil
}

func (keystore GcpKeystore) ReadAndDecrypt() (*api.InitResponse, error) {
	bucket := keystore.storageClient.Bucket(keystore.gcsBucketName)

	ctx := context.Background()
	unsealKeysObject, err := bucket.Object("unseal-keys.json.enc").NewReader(ctx)
	if err != nil {
		return nil, err
	}

	defer unsealKeysObject.Close()

	unsealKeysData, err := ioutil.ReadAll(unsealKeysObject)
	if err != nil {
		return nil, err
	}

	unsealKeysDecryptRequest := &cloudkms.DecryptRequest{
		Ciphertext: string(unsealKeysData),
	}

	unsealKeysDecryptResponse, err := keystore.kmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(keystore.kmsKeyID, unsealKeysDecryptRequest).Do()
	if err != nil {
		return nil, err
	}

	var initResponse api.InitResponse

	unsealKeysPlaintext, err := base64.StdEncoding.DecodeString(unsealKeysDecryptResponse.Plaintext)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(unsealKeysPlaintext, &initResponse); err != nil {
		return nil, err
	}

	return &initResponse, nil
}
