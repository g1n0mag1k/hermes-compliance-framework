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
