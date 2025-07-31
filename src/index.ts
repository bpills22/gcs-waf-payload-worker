import type { IRequest } from "itty-router";
import { AutoRouter } from "itty-router";
import { decode } from "./matched_data";
import { inflate } from "pako"; // Ensure pako is installed in package.json

type Env = {
  MATCHED_PAYLOAD_PRIVATE_KEY: string;
  OWASP_PRIVATE_KEY: string;
  WAF_LOGS_BUCKET: R2Bucket;
};

const router = AutoRouter();

router.put("/logs/:logdata+", async (req: IRequest, env: Env) => {
  // Handle ownership challenge files
  if (/\/ownership-challenge-[a-fA-F0-9]{8}\.txt/.test(req.url)) {
    return new Response("OK");
  }

  // Ignore Cloudflare's test.txt.gz
  if (/\d{8}\/test\.txt\.gz/.test(req.url)) {
    return new Response("OK");
  }

  // Read raw gzipped body
  const raw = await req.arrayBuffer();
  if (!raw || raw.byteLength === 0) {
    return new Response("OK (empty payload)");
  }

  // Inflate gzip → NDJSON string
  const ndjson = inflate(new Uint8Array(raw), { to: "string" });

  // Split into lines, parse each full Firewall Event log object
  const events = ndjson
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line));

  // Add decrypted payloads to each full log
  const enriched = await Promise.all(
    events.map(async (event) => {
      let decrypted = null;

      // Try both top-level and Metadata field for encrypted payload
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

  // Store enriched logs in R2
  if (enriched.length > 0) {
    const dateFolder = new Date().toISOString().split("T")[0];
    const filename = `waf-logs/${dateFolder}/${Date.now()}.json`;

    await env.WAF_LOGS_BUCKET.put(filename, JSON.stringify(enriched, null, 2), {
      httpMetadata: { contentType: "application/json" },
    });

    console.log(
      `Uploaded ${enriched.length} WAF events with decrypted payloads`
    );
  }

  return new Response("OK");
});

// Catch-all
router.all("*", () => new Response("Not Found", { status: 404 }));

export default { ...router };
