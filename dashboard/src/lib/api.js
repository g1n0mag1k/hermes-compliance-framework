const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8787";
const API_KEY = import.meta.env.VITE_API_KEY || "";

export { API_URL, API_KEY };

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

export async function fetchScanHistory(apiKey, days = 7) {
  const response = await fetch(
    `${API_URL}/v1/scan-history?days=${days}`,
    {
      headers: {
        "X-API-Key": apiKey,
        "Content-Type": "application/json",
      },
    }
  );
  if (!response.ok) {
    throw new Error(`scan-history fetch failed: ${response.status}`);
  }
  return response.json();
}

export async function fetchWorkspaces() {
  const response = await fetch(`${API_URL}/v1/workspaces`, {
    method: "GET",
    headers: {
      "X-API-Key": API_KEY,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Workspaces request failed with HTTP ${response.status}`);
  }

  return response.json();
}

/** Current authenticated workspace (includes role for RBAC). */
export async function fetchCurrentWorkspace() {
  const response = await fetch(`${API_URL}/v1/workspace`, {
    method: "GET",
    headers: {
      "X-API-Key": API_KEY,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Workspace request failed with HTTP ${response.status}`);
  }

  return response.json();
}

export async function updateSentryConfig() {
  const response = await fetch(`${API_URL}/api/v1/sentry/config`, {
    method: "POST",
    headers: {
      "X-API-Key": API_KEY,
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`Sentry config update failed with HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * Drata sync is not implemented server-side. The endpoint answers HTTP 501
 * with the configuration state (NOT_CONFIGURED / CONFIGURED / ...), which is
 * returned here. Any other response is treated as an error.
 */
export async function syncDrataConfig() {
  const response = await fetch(`${API_URL}/api/v1/drata/config`, {
    method: "POST",
    headers: {
      "X-API-Key": API_KEY,
      Accept: "application/json",
    },
  });
  if (response.status === 501) {
    return response.json();
  }
  throw new Error(`Drata status check failed with HTTP ${response.status}`);
}

/**
 * Drata integration status computed from local Hermes state only (offline
 * config check + evidence outbox counts). Never contacts Drata and never
 * returns the Drata URL or API key.
 */
export async function fetchDrataStatus() {
  const response = await fetch(`${API_URL}/v1/integrations/drata/status`, {
    method: "GET",
    headers: {
      "X-API-Key": API_KEY,
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    const err = new Error(`Drata status request failed with HTTP ${response.status}`);
    err.status = response.status;
    throw err;
  }
  return response.json();
}
