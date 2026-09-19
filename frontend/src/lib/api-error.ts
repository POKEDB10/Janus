import axios from "axios";

export function getApiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (error.code === "ECONNABORTED") return "The request timed out.";
    if (!error.response) return "The backend could not be reached.";
    return `The backend returned ${error.response.status}.`;
  }
  return error instanceof Error ? error.message : "The request failed.";
}
