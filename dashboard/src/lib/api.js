const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8787";
const API_KEY = import.meta.env.VITE_API_KEY || "";

export { API_URL };

export async function fetchStatus() {
  const response = await fetch(`${API_URL}/v1/status`, {
    method: "GET",
    headers: {
      "X-API-Key": API_KEY,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Status request failed with HTTP ${response.status}`);
  }

  return response.json();
}

export async function runTrialScan() {
  const response = await fetch(`${API_URL}/v1/trial-scan`, {
    method: "POST",
    headers: {
      "X-API-Key": API_KEY,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    const detail = await response.text();
    const err = new Error(
      response.status === 429
        ? "Trial scan quota exhausted or trial window expired"
        : `Trial scan failed with HTTP ${response.status}`
    );
    err.status = response.status;
    err.detail = detail;
    throw err;
  }

  return response.json();
}
