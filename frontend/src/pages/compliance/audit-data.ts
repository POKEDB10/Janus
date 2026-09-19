import type { ComplianceReport, Finding, JsonValue } from "../../types";

export interface AlgorithmComparison {
  finding: Finding;
  parameter: string;
  detected: string;
  required: string;
}

function normalise(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function displayValue(value: JsonValue): string | null {
  if (value === null) return null;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function evaluatedValue(parameter: string, evaluated: Record<string, JsonValue>): string | null {
  const direct = Object.entries(evaluated).find(([key]) => normalise(key) === normalise(parameter));
  if (direct) return displayValue(direct[1]);

  const aliases: Record<string, string[]> = {
    espencryption: ["esp_encryption"],
    espauthentication: ["esp_auth"],
    diffiehellmangroup: ["dh_group", "ike_dh_group"],
    perfectforwardsecrecy: ["pfs_enabled"],
    salifetime: ["sa_lifetime_seconds"],
  };
  const match = aliases[normalise(parameter)]?.map((key) => [key, evaluated[key]] as const).find(([, value]) => value !== undefined);
  return match ? displayValue(match[1]) : null;
}

export function buildAlgorithmComparisons(compliance: ComplianceReport): AlgorithmComparison[] {
  const evaluated = compliance.evaluated_parameters ?? {};
  return compliance.findings.flatMap((finding) => {
    const detected = evaluatedValue(finding.parameter, evaluated);
    const required = finding.remediation ?? finding.recommendation;
    if (!detected || !required) return [];
    return [{ finding, parameter: finding.parameter, detected, required }];
  });
}

export function markedRemediationLines(config: string, comparisons: AlgorithmComparison[]): number[] {
  const tokens = comparisons.flatMap((comparison) => [comparison.finding.value, comparison.detected])
    .filter((value): value is string => Boolean(value && value.length > 3))
    .map((value) => value.toLowerCase());
  if (!tokens.length) return [];
  return config.split("\n").flatMap((line, index) => tokens.some((token) => line.toLowerCase().includes(token)) ? [index + 1] : []);
}
