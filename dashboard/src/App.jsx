import { useCallback, useEffect, useState } from "react";
import PortfolioHeader from "./components/PortfolioHeader.jsx";
import ClientTable from "./components/ClientTable.jsx";
import { API_URL, fetchStatus } from "./lib/api.js";

const POLL_INTERVAL_MS = 30_000;

export default function App() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadStatus = useCallback(async () => {
    try {
      const data = await fetchStatus();
      setStatus(data);
      setError(null);
    } catch {
      setError(`Unable to reach Hermes Relay at ${API_URL}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStatus();
    const timer = setInterval(loadStatus, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [loadStatus]);

  if (loading && !status && !error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-canvas">
        <p className="animate-pulse text-sm font-medium text-navy">
          Connecting to Hermes Relay...
        </p>
      </div>
    );
  }

  if (error && !status) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-canvas px-6">
        <p className="text-center text-sm font-medium text-critical">{error}</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-canvas">
      <PortfolioHeader status={status} />
      <main className="mx-auto max-w-7xl px-6 py-8">
        {error ? (
          <p className="mb-4 text-sm font-medium text-critical">{error}</p>
        ) : null}
        <ClientTable status={status} />
      </main>
    </div>
  );
}
