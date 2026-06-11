# Migration Procedure: S3 SSE-C to SSE-KMS

## Background

The vault-init S3 backend previously used SSE-C (Server-Side Encryption with Customer-Provided Keys), where the AES-256 encryption key was passed as the `AWS_ENCRYPTION_KEY` environment variable. This exposed the key in the pod spec, process environment, and any observability tooling that captures env vars.

The new implementation uses SSE-KMS (Server-Side Encryption with AWS KMS), where the data encryption key never leaves AWS KMS. The pod only needs the KMS key ARN/ID (`AWS_KMS_KEY_ID`) and IAM permissions to call `kms:Encrypt`/`kms:Decrypt`/`kms:GenerateDataKey` on that key.

## Prerequisites

- AWS KMS key (CMK) created in the same region as the S3 bucket
- IAM role used by vault-init must have the following KMS permissions on the CMK:
  - `kms:Encrypt`
  - `kms:Decrypt`
  - `kms:GenerateDataKey`
- IAM role must retain `s3:GetObject` and `s3:PutObject` on the vault bucket

## Migration Steps

### 1. Identify Existing Encrypted Objects

```bash
# List the vault objects in the S3 bucket
aws s3 ls s3://<BUCKET_NAME>/<BUCKET_PATH>/vault/
```

Expected objects:
- `vault/unseal-keys.json`
- `vault/root-token`

### 2. Download Objects Using the Old SSE-C Key

```bash
# Download unseal-keys.json with SSE-C
aws s3api get-object \
  --bucket <BUCKET_NAME> \
  --key <BUCKET_PATH>/vault/unseal-keys.json \
  --sse-customer-algorithm AES256 \
  --sse-customer-key <BASE64_ENCODED_ENCRYPTION_KEY> \
  unseal-keys.json

# Download root-token with SSE-C
aws s3api get-object \
  --bucket <BUCKET_NAME> \
  --key <BUCKET_PATH>/vault/root-token \
  --sse-customer-algorithm AES256 \
  --sse-customer-key <BASE64_ENCODED_ENCRYPTION_KEY> \
  root-token
```

### 3. Re-upload Objects Using SSE-KMS

```bash
# Upload unseal-keys.json with SSE-KMS
aws s3api put-object \
  --bucket <BUCKET_NAME> \
  --key <BUCKET_PATH>/vault/unseal-keys.json \
  --body unseal-keys.json \
  --server-side-encryption aws:kms \
  --ssekms-key-id <KMS_KEY_ARN>

# Upload root-token with SSE-KMS
aws s3api put-object \
  --bucket <BUCKET_NAME> \
  --key <BUCKET_PATH>/vault/root-token \
  --body root-token \
  --server-side-encryption aws:kms \
  --ssekms-key-id <KMS_KEY_ARN>
```

### 4. Update vault-init Deployment Configuration

Replace the environment variable in the pod spec / Helm values:

**Before:**
```yaml
env:
  - name: CLOUD_PROVIDER
    value: "aws-s3"
  - name: AWS_ENCRYPTION_KEY
    value: "<plaintext-aes-key>"  # INSECURE
  - name: AWS_BUCKET_NAME
    value: "<bucket>"
  - name: AWS_BUCKET_PATH
    value: "<path>"
```

**After:**
```yaml
env:
  - name: CLOUD_PROVIDER
    value: "aws-s3"
  - name: AWS_KMS_KEY_ID
    value: "arn:aws:kms:<region>:<account>:key/<key-id>"
  - name: AWS_BUCKET_NAME
    value: "<bucket>"
  - name: AWS_BUCKET_PATH
    value: "<path>"
```

### 5. Deploy Updated vault-init

Roll out the updated vault-init image with the new configuration. Verify the pod starts successfully and can read the re-encrypted objects.

### 6. Verify Unseal Works

```bash
# Check vault-init logs for successful unseal
kubectl logs <vault-init-pod> | grep -i "unseal"
```

### 7. Clean Up

- Remove `AWS_ENCRYPTION_KEY` from all deployment manifests, Helm values, and secret stores
- Rotate or revoke the old SSE-C key material
- Consider adding a bucket policy that denies PutObject without SSE-KMS to prevent accidental plaintext or SSE-C uploads:

```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::<BUCKET_NAME>/<BUCKET_PATH>/vault/*",
  "Condition": {
    "StringNotEquals": {
      "s3:x-amz-server-side-encryption": "aws:kms"
    }
  }
}
```

## Rollback

If issues arise, the rollback path is:
1. Re-download objects using SSE-KMS (`aws s3api get-object` without SSE-C flags)
2. Re-upload with the old SSE-C key
3. Revert the vault-init deployment to the previous image/config

## Security Notes

- The old `AWS_ENCRYPTION_KEY` should be treated as compromised if it was ever visible in pod specs, logs, or monitoring systems. Even after migration, rotate any secrets that were protected solely by that key.
- With SSE-KMS, access control is enforced by both the S3 bucket policy AND the KMS key policy. An attacker needs both `s3:GetObject` and `kms:Decrypt` to read the vault secrets.
- The KMS key policy should restrict `kms:Decrypt` to only the vault-init IAM role and break-glass admin roles.
