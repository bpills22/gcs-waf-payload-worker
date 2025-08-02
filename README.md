# GCS WAF Payload Worker

A Cloudflare Worker that processes WAF Firewall Event logs from Logpush, decrypts `encrypted_matched_data` payloads, and uploads the enriched logs to **Google Cloud Storage (GCS)**.

## Overview

This Worker performs the following operations:

1. **Receives** gzipped NDJSON WAF log batches via Cloudflare Logpush
2. **Inflates and parses** the logs
3. **Decrypts** any `encrypted_matched_data` fields using the provided RSA private keys
4. **Adds** a `decrypted_matched_data` field to each log
5. **Uploads** the enriched JSON logs to your specified GCS bucket

## Requirements

- **Cloudflare Account** with Workers enabled
- **Google Cloud Platform (GCP)** account with:
  - A GCS bucket for logs
  - A Service Account with the `Storage Object Creator` role
- **Wrangler CLI** installed

```bash
npm install -g wrangler
```

## Setup Instructions

### 1. Clone This Repository

```bash
git clone https://github.com/bpills22/gcs-waf-payload-worker.git
cd gcs-waf-payload-worker
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Create a GCS Service Account and Key

1. In the Google Cloud Console, navigate to:
   - **IAM & Admin** → **Service Accounts** → **Create Service Account**
2. Grant the following role:
   - **Storage Object Creator**
3. Create a JSON key and download it to your computer
4. **Important:** Do not commit this JSON file to GitHub. Ensure `.gitignore` includes it.

### 4. Configure Worker Secrets

This Worker requires three secrets:

| Secret Name | Description |
|-------------|-------------|
| `GCS_SERVICE_ACCOUNT_KEY` | Contents of the GCS service account JSON key file (single line) |
| `MATCHED_PAYLOAD_PRIVATE_KEY` | Private key for your matched payload decryption |
| `OWASP_PRIVATE_KEY` | Private key for OWASP payload decryption |

#### Convert GCS JSON Key to One Line

```bash
cat your-key.json | jq -c .
```

Copy the output (a single JSON line) and store it in the Worker:

```bash
npx wrangler secret put GCS_SERVICE_ACCOUNT_KEY
# Paste the one-liner JSON when prompted
```

#### Add the Other Secrets

```bash
npx wrangler secret put MATCHED_PAYLOAD_PRIVATE_KEY
npx wrangler secret put OWASP_PRIVATE_KEY
```

### 5. Configure wrangler.toml

Create or update your `wrangler.toml` file:

```toml
name = "gcs-waf-payload-decoder"
main = "src/index.ts"
compatibility_date = "2025-08-01"

[vars]
BUCKET_NAME = "waflz-logs"
```

Replace `BUCKET_NAME` with your GCS bucket name.

### 6. Deploy the Worker

```bash
npx wrangler deploy
```

### 7. Add a Route and Custom Domain (Optional)

In the Cloudflare dashboard:

1. Go to **Workers & Pages**
2. Select your Worker → **Settings** → **Domains & Routes**
3. Add a route like:
   ```
   gcs-waflz.example.com/*
   ```

## Testing

A test route `/gcs-test` is included to confirm GCS connectivity.

```bash
curl "https://<your-worker-domain>/gcs-test"
```

**Expected output:**
```yaml
✅ GCS access token acquired: ya29...
```

## Logpush Setup (Cloudflare → GCS)

1. In the Cloudflare Dashboard, go to your zone:
   - **Analytics & Logs** → **Logpush** → **S3 Compatible**
2. Create a job:
   - **Destination:** HTTPS (point to your Worker URL, e.g., `https://gcs-waflz.example.com/logs`)
   - **Dataset:** Firewall Events (WAF)
   
3. Enable the job

## Viewing Logs in GCS

In the GCS console:

1. Navigate to your bucket (`BUCKET_NAME`)
2. Logs will be stored in the following structure:
   ```
   waf-logs/YYYY-MM-DD/timestamp.json
   ```
3. Each file contains an array of enriched log objects with decrypted payloads

## Example Output

```json
{
  "Action": "block",
  "ClientRequestHost": "example.com",
  "ClientRequestQuery": "?id=1%20OR%201=1",
  "Metadata": {
    "encrypted_matched_data": "A0yU3g...",
    "matched_vars": "[\"http.request.uri\"]"
  },
  "decrypted_matched_data": "{\"http.request.uri\":{\"before\":\"/?id=1 \",\"content\":\"OR 1=1\"}}"
}
```

## Security Notes

⚠️ **Important Security Considerations:**

- Never commit your private keys or GCS service account JSON to GitHub
- Always use Wrangler secrets for sensitive values
- Ensure your GCS bucket is private and properly configured
- Regularly rotate your service account keys and private keys

## License

MIT License