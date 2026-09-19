#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const options = (name) => args.flatMap((value, index) => value === name && args[index + 1] ? [args[index + 1]] : []);

if (args.includes("--help")) {
  console.log("Usage: node scripts/record-fixtures.mjs --capture <capture-id> [--capture <capture-id>] [--base-url <url>] [--include-scenario-04]");
  console.log("       node scripts/record-fixtures.mjs --all-samples [--base-url <url>] [--include-scenario-04]");
  console.log("Reads JANUS_API_KEY or VITE_API_KEY when the backend requires authentication.");
  process.exit(0);
}

const requestedCaptureIds = options("--capture");
const baseUrl = (option("--base-url") ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const apiKey = process.env.JANUS_API_KEY ?? process.env.VITE_API_KEY;
const includeScenario04 = args.includes("--include-scenario-04");

if (!requestedCaptureIds.length && !args.includes("--all-samples")) {
  console.error("Pass --capture <capture-id> or --all-samples.");
  process.exit(1);
}

const headers = apiKey ? { "X-API-Key": apiKey } : {};
const outputDir = resolve("frontend/src/fixtures");

function stripSecrets(value) {
  if (Array.isArray(value)) return value.map(stripSecrets);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => !/(token|api[_-]?key|authorization|secret|password)/i.test(key))
      .map(([key, item]) => [key, stripSecrets(item)]),
  );
}

async function record(captureId, name, path) {
  const response = await fetch(`${baseUrl}${path}`, { headers });
  if (!response.ok) throw new Error(`${name}: ${response.status} ${response.statusText}`);
  const data = stripSecrets(await response.json());
  await writeFile(resolve(outputDir, `${captureId}.${name}.json`), `${JSON.stringify(data, null, 2)}\n`);
}

await mkdir(outputDir, { recursive: true });
let captureIds = requestedCaptureIds;
if (args.includes("--all-samples")) {
  const response = await fetch(`${baseUrl}/api/samples`, { headers });
  if (!response.ok) throw new Error(`samples: ${response.status} ${response.statusText}`);
  const samples = await response.json();
  if (!Array.isArray(samples) || !samples.every((sample) => sample && typeof sample === "object" && typeof sample.id === "string")) {
    throw new Error("samples: unexpected response shape");
  }
  captureIds = [...new Set([...captureIds, ...samples.map((sample) => sample.id)])];
}

for (const captureId of captureIds) {
  if (captureId.toLowerCase().includes("scenario_04") && !includeScenario04) {
    console.warn(`Skipping ${captureId}: pass --include-scenario-04 after verifying the backend override is removed.`);
    continue;
  }
  await record(captureId, "results", `/api/analysis/${encodeURIComponent(captureId)}/results`);
  await record(captureId, "status", `/api/analysis/${encodeURIComponent(captureId)}/status`);
  await record(captureId, "report-status", `/api/report/${encodeURIComponent(captureId)}/status`);
  console.log(`Recorded API responses for ${captureId} in ${outputDir}`);
}
