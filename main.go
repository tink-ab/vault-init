// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/kelseyhightower/vault-init/pkg/keystore"
)

var (
	checkInterval string
)

const (
	providerGcp   = "gcp"
	providerAws   = "aws"
	providerAwsS3 = "aws-s3"
)

func getEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s must be set and not empty", name)
	}
	return value
}

func createAwsConfig() *keystore.AwsConfig {
	retryOnCredentialsWait, err := time.ParseDuration(os.Getenv("AWS_RETRY_ON_CREDENTIALS_WAIT"))
	if err != nil || retryOnCredentialsWait == 0 {
		retryOnCredentialsWait = 5 * time.Second
	}

	return &keystore.AwsConfig{
		Endpoint:                os.Getenv("AWS_ENDPOINT"),
		RetryOnCredentialsWait:  retryOnCredentialsWait,
	}
}

func createGcpKeystore() *keystore.GcpKeystore {
	gcsBucketName := getEnv("GCS_BUCKET_NAME")
	kmsKeyID := getEnv("KMS_KEY_ID")

	gcpKeystore, err := keystore.NewGcpKeystore(gcsBucketName, kmsKeyID)
	if err != nil {
		log.Fatalln(err)
	}

	return gcpKeystore
}

func createAwsKeystore() *keystore.AwsKeystore {
	awsKeystore, err := keystore.NewAwsKeystore(&keystore.AwsKeystoreConfig{
		AwsConfig:   createAwsConfig(),
		KmsKeyID:    getEnv("KMS_KEY_ID"),
		SecretsPath: getEnv("AWS_SECRETS_PATH"),
	})
	if err != nil {
		log.Fatalf("failed to initialize aws store: %v", err)
	}

	return awsKeystore
}

func createAwsS3Keystore() *keystore.AwsS3Keystore {
	s3Keystore, err := keystore.NewAwsS3Keystore(&keystore.AwsS3KeystoreConfig{
		AwsConfig:  createAwsConfig(),
		KmsKeyID:   getEnv("AWS_KMS_KEY_ID"),
		BucketName: getEnv("AWS_BUCKET_NAME"),
		BucketPath: getEnv("AWS_BUCKET_PATH"),
	})
	if err != nil {
		log.Fatalf("failed to initialize aws store: %v", err)
	}

	return s3Keystore
}

func createKeystore() keystore.Keystore {
	cloudProvider := os.Getenv("CLOUD_PROVIDER")
	if cloudProvider == "" {
		cloudProvider = providerGcp
	}

	switch cloudProvider {
	case providerGcp:
		return createGcpKeystore()
	case providerAws:
		return createAwsKeystore()
	case providerAwsS3:
		return createAwsS3Keystore()
	}

	log.Fatalf("Unknow CLOUD_PROVIDER: %s", cloudProvider)
	return nil
}

func main() {
	log.Println("Starting the vault-init service...")

	var initOne = flag.String("init-one", "", "Specify a single pod name where vault should be initialized")
	flag.Parse()

	checkInterval = os.Getenv("CHECK_INTERVAL")
	if checkInterval == "" {
		checkInterval = "10"
	}

	i, err := strconv.Atoi(checkInterval)
	if err != nil {
		log.Fatalf("CHECK_INTERVAL is invalid: %s", err)
	}

	checkIntervalDuration := time.Duration(i) * time.Second

	keystoreClient := createKeystore()
	defer keystoreClient.Close()

	podName := os.Getenv("POD_NAME")

	vaultConfig := api.DefaultConfig()
	vaultClient, err := api.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Failed to create vault client %s", err)
	}

	signalCh := make(chan os.Signal)
	signal.Notify(signalCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
	)

	stop := func() {
		log.Printf("Shutting down")
		keystoreClient.Close()
		os.Exit(0)
	}

	for {
		checkVaultStatus(vaultClient, keystoreClient, *initOne, podName)
		select {
		case <-signalCh:
			stop()
		case <-time.After(checkIntervalDuration):
		}
	}
}

func checkVaultStatus(vaultClient *api.Client, keystoreClient keystore.Keystore, initOne string, podName string) {
	response, err := vaultClient.Sys().Health()
	if err != nil {
		log.Println(err)
		return
	}

	if !response.Initialized {
		if initOne != "" && podName == initOne {
			log.Println("Vault is not initialized. Initializing...")
			initialize(vaultClient, keystoreClient)
		}
		log.Println("Vault is sealed. Unsealing...")
		unseal(vaultClient, keystoreClient)
		return
	}
	if response.Sealed {
		log.Println("Vault is sealed. Unsealing...")
		unseal(vaultClient, keystoreClient)
		return
	}
	if response.Standby {
		log.Println("Vault is unsealed and in standby mode.")
		return
	}
}

func initialize(vaultClient *api.Client, keystoreClient keystore.Keystore) {
	initRequest := api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	initResponse, err := vaultClient.Sys().Init(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	err = keystoreClient.EncryptAndWrite(initResponse)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Initialization complete.")
}

func unseal(vaultClient *api.Client, keystoreClient keystore.Keystore) {
	initResponse, err := keystoreClient.ReadAndDecrypt()
	if err != nil {
		log.Println(err)
		return
	}

	for _, key := range initResponse.KeysB64 {
		done, err := unsealOne(vaultClient, key)
		if done {
			return
		}

		if err != nil {
			log.Println(err)
			return
		}
	}
}

func unsealOne(vaultClient *api.Client, key string) (bool, error) {
	unsealResponse, err := vaultClient.Sys().Unseal(key)
	if err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil
}
