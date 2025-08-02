import type { IRequest } from "itty-router";
import { AutoRouter } from "itty-router";
import { decode } from "./matched_data";
import { inflate } from "pako"; // gzip inflate

type Env = {
  MATCHED_PAYLOAD_PRIVATE_KEY: string; // Managed ruleset key
  OWASP_PRIVATE_KEY: string; // OWASP ruleset key
  GCS_SERVICE_ACCOUNT_KEY: string; // JSON for service account key
};

// === Helper: Safe Base64URL from Uint8Array ===
function uint8ToBase64Url(uint8: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < uint8.length; i++) {
    binary += String.fromCharCode(uint8[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// === GCS Access Token Helper ===
async function getGcsAccessToken(
  serviceAccountKeyJson: string
): Promise<string> {
  const serviceAccount = JSON.parse(serviceAccountKeyJson);
  const now = Math.floor(Date.now() / 1000);

  const jwtHeader = { alg: "RS256", typ: "JWT" };
  const jwtClaim = {
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/devstorage.read_write",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  // Polyfill base64url
  const base64url = (input: string) =>
    btoa(unescape(encodeURIComponent(input)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

  // PEM → DER
  const pemToDer = (pem: string): Uint8Array => {
    const normalizedPem = pem.replace(/\\n/g, "\n");
    const b64 = normalizedPem
      .replace(/-----[^-]+-----/g, "")
      .replace(/\s+/g, "");
    const binaryString = atob(b64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  };

  const encHeader = base64url(JSON.stringify(jwtHeader));
  const encClaim = base64url(JSON.stringify(jwtClaim));

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(serviceAccount.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const encoder = new TextEncoder();
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    encoder.encode(`${encHeader}.${encClaim}`)
  );

  const encSignature = uint8ToBase64Url(new Uint8Array(signature));
  const jwt = `${encHeader}.${encClaim}.${encSignature}`;

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  const data = (await res.json()) as { access_token?: string };
  if (!data.access_token) {
    throw new Error(`Failed to get GCS access token: ${JSON.stringify(data)}`);
  }
  return data.access_token;
}

// === Router ===
const router = AutoRouter();

// === PUT endpoint for Logpush ===
router.put("/logs/:logdata+", async (req: IRequest, env: Env) => {
  // Handle CF ownership file
  if (/\/ownership-challenge-[a-fA-F0-9]{8}\.txt/.test(req.url)) {
    return new Response("OK");
  }

  // Skip Cloudflare test.txt.gz
  if (/\d{8}\/test\.txt\.gz/.test(req.url)) {
    return new Response("OK");
  }

  // Read gzipped body
  const raw = await req.arrayBuffer();
  if (!raw || raw.byteLength === 0) {
    return new Response("OK (empty payload)");
  }

  // Gzip inflate → NDJSON string
  const ndjson = inflate(new Uint8Array(raw), { to: "string" });

  // Parse each line into JSON
  const events = ndjson
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));

  // Enrich each event with decrypted payload
  const enriched = await Promise.all(
    events.map(async (event) => {
      let decrypted = null;
      const encData =
        event.encrypted_matched_data || event.Metadata?.encrypted_matched_data;
      if (encData) {
        decrypted =
          (await decode(encData, env.MATCHED_PAYLOAD_PRIVATE_KEY)) ||
          (await decode(encData, env.OWASP_PRIVATE_KEY));
      }
      return {
        ...event,
        decrypted_matched_data: decrypted,
      };
    })
  );

  // Upload to GCS
  if (enriched.length > 0) {
    const dateFolder = new Date().toISOString().split("T")[0];
    const filename = `waf-logs/${dateFolder}/${Date.now()}.json`;
    const bucketName = "waflz-logs"; // Your GCS bucket

    const accessToken = await getGcsAccessToken(env.GCS_SERVICE_ACCOUNT_KEY);

    const uploadUrl = `https://storage.googleapis.com/upload/storage/v1/b/${bucketName}/o?uploadType=media&name=${filename}`;

    const uploadRes = await fetch(uploadUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(enriched, null, 2),
    });

    if (!uploadRes.ok) {
      console.error(
        `Failed to upload to GCS: ${uploadRes.status} ${await uploadRes.text()}`
      );
      return new Response(`GCS Upload Failed`, { status: 500 });
    }

    console.log(`Uploaded ${enriched.length} WAF events to GCS`);
  }

  return new Response("OK");
});

// Catch-all
router.all("*", () => new Response("Not Found", { status: 404 }));

export default { ...router };
