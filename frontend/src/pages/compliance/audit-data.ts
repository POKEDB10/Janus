import type { ComplianceReport, Finding, JsonValue } from "../../types";

export interface AlgorithmComparison {
  finding?: Finding;
  parameter: string;
  detected: string;
  required: string;
  status: "PASS" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "ADVISORY";
}

function normalise(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function displayValue(value: JsonValue): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function evaluatedValue(parameter: string, evaluated: Record<string, JsonValue>): string | null {
  const direct = Object.entries(evaluated).find(([key]) => normalise(key) === normalise(parameter));
  if (direct && direct[1] !== null && direct[1] !== undefined) return displayValue(direct[1]);

  const aliases: Record<string, string[]> = {
    espencryption: ["esp_encryption"],
    espauthentication: ["esp_auth"],
    diffiehellmangroup: ["dh_group", "ike_dh_group"],
    perfectforwardsecrecy: ["pfs_enabled"],
    salifetime: ["sa_lifetime_seconds"],
    ikeversion: ["ike_version"],
    pqcstatus: ["pqc_status"],
  };
  const match = aliases[normalise(parameter)]
    ?.map((key) => [key, evaluated[key]] as const)
    .find(([, value]) => value !== undefined && value !== null);
  return match ? displayValue(match[1]) : null;
}

interface StandardParamSpec {
  name: string;
  keys: string[];
  required: string;
  format?: (val: string, evaluated: Record<string, JsonValue>) => string;
  pqc?: boolean;
}

const STANDARD_PARAMS: StandardParamSpec[] = [
  {
    name: "ESP Encryption",
    keys: ["esp_encryption"],
    required: "AES-GCM-128 / AES-GCM-256 (RFC 8221 §5)",
  },
  {
    name: "ESP Authentication",
    keys: ["esp_auth"],
    required: "Integrated AEAD or HMAC-SHA2-256 (RFC 8221 §5)",
    format: (val, evaluated) => {
      const enc = String(evaluated.esp_encryption || "").toUpperCase();
      if (val === "AUTH_NONE" && enc.includes("GCM")) return "AUTH_NONE (AEAD ICV-16)";
      return val;
    },
  },
  {
    name: "Diffie-Hellman Group",
    keys: ["dh_group", "ike_dh_group"],
    required: "Group 19+ (ECP-256) or Group 14+ (MODP-2048) (RFC 8247 §2.4)",
    format: (val) => {
      if (val === "19") return "Group 19 (ECP-256)";
      if (val === "20") return "Group 20 (ECP-384)";
      if (val === "14") return "Group 14 (MODP-2048)";
      if (val === "2") return "Group 2 (MODP-1024 - Insecure)";
      if (val === "1") return "Group 1 (MODP-768 - Broken)";
      return `Group ${val}`;
    },
  },
  {
    name: "Perfect Forward Secrecy",
    keys: ["pfs_enabled"],
    required: "Mandatory PFS for Child SAs (NIST SP 800-77 Rev. 1)",
    format: (val) => (val === "true" ? "Enabled (true)" : "Disabled (false)"),
  },
  {
    name: "SA Rotation Lifetime",
    keys: ["sa_lifetime_seconds"],
    required: "≤ 28800s (1h – 8h recommended) (NIST SP 800-77 §5.4)",
    format: (val) => {
      const num = Number(val);
      if (num === 3600) return "3600s (1h)";
      if (num === 14400) return "14400s (4h)";
      if (num === 28800) return "28800s (8h)";
      if (num === 86400) return "86400s (24h - Deprecated)";
      return `${val}s`;
    },
  },
  {
    name: "IKE Protocol Version",
    keys: ["ike_version"],
    required: "IKEv2 (RFC 7296 / RFC 8247)",
  },
  {
    name: "Post-Quantum Readiness",
    keys: ["pqc_status"],
    required: "Hybrid ML-KEM Key Exchange (RFC 9370 / FIPS 203)",
    pqc: true,
    format: (val) => {
      if (val === "CRQC_VULNERABLE") return "CRQC_VULNERABLE (Classical ECDH)";
      if (val === "PQC_HYBRID") return "PQC_HYBRID (RFC 9370)";
      return val;
    },
  },
];

export function buildAlgorithmComparisons(compliance: ComplianceReport): AlgorithmComparison[] {
  const evaluated = (compliance.evaluated_parameters ?? {}) as Record<string, JsonValue>;
  const findings = compliance.findings ?? [];
  const results: AlgorithmComparison[] = [];
  const coveredFindings = new Set<string>();

  // 1. Iterate through standard parameters and map against evaluated_parameters & findings
  for (const spec of STANDARD_PARAMS) {
    let rawVal: string | null = null;
    for (const key of spec.keys) {
      if (evaluated[key] !== undefined && evaluated[key] !== null) {
        rawVal = displayValue(evaluated[key]);
        break;
      }
    }

    // Find any finding that corresponds to this parameter
    const matchingFinding = findings.find((f) => {
      const normF = normalise(f.parameter);
      const normSpec = normalise(spec.name);
      return normF === normSpec || spec.keys.some((k) => normalise(k) === normF);
    });

    if (matchingFinding) {
      coveredFindings.add(matchingFinding.rule_id);
      const detected = matchingFinding.value ?? (rawVal ? (spec.format ? spec.format(rawVal, evaluated) : rawVal) : "Detected weak setting");
      const required = matchingFinding.remediation ?? matchingFinding.recommendation ?? spec.required;
      const severity = (matchingFinding.severity?.toUpperCase() || "HIGH") as AlgorithmComparison["status"];
      results.push({
        finding: matchingFinding,
        parameter: spec.name,
        detected,
        required,
        status: severity,
      });
    } else if (rawVal !== null) {
      const detected = spec.format ? spec.format(rawVal, evaluated) : rawVal;
      results.push({
        parameter: spec.name,
        detected,
        required: spec.required,
        status: spec.pqc ? "ADVISORY" : "PASS",
      });
    }
  }

  // 2. Add any remaining findings not covered in standard list
  for (const f of findings) {
    if (coveredFindings.has(f.rule_id)) continue;
    const detected = evaluatedValue(f.parameter, evaluated) ?? f.value ?? "Observed non-compliant setting";
    const required = f.remediation ?? f.recommendation ?? "Remediation recommended per IPsec RFC specification";
    const severity = (f.severity?.toUpperCase() || "HIGH") as AlgorithmComparison["status"];
    results.push({
      finding: f,
      parameter: f.parameter,
      detected,
      required,
      status: severity,
    });
  }

  return results;
}

export function markedRemediationLines(config: string, comparisons: AlgorithmComparison[]): number[] {
  const nonPass = comparisons.filter((c) => c.status !== "PASS");
  const tokens = nonPass
    .flatMap((comparison) => [comparison.finding?.value, comparison.detected])
    .filter((value): value is string => Boolean(value && value.length > 3))
    .map((value) => value.toLowerCase());
  if (!tokens.length) return [];
  return config.split("\n").flatMap((line, index) =>
    tokens.some((token) => line.toLowerCase().includes(token)) ? [index + 1] : []
  );
}
