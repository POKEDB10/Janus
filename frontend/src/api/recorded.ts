import type { AnalysisResults } from "../types";

export class RecordedFixtureUnavailableError extends Error {
  constructor(captureId: string) {
    super(`No recorded sample is installed for ${captureId}.`);
    this.name = "RecordedFixtureUnavailableError";
  }
}

const recordedResults = import.meta.glob<AnalysisResults>("../fixtures/*.results.json", {
  eager: true,
  import: "default",
});

export function getRecordedAnalysis(captureId: string): AnalysisResults {
  const fixture = Object.entries(recordedResults).find(([path]) =>
    path.endsWith(`/${captureId}.results.json`),
  )?.[1];

  if (!fixture) {
    throw new RecordedFixtureUnavailableError(captureId);
  }

  return fixture;
}
