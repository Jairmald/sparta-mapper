import { useState } from "react";

const API_BASE = "http://localhost:8000";

// Parent: EX-0016 -> /technique/EX-0016/ ; sub: EX-0016.01 -> /technique/EX-0016/01/
function techniqueUrl(externalId) {
  return `https://sparta.aerospace.org/technique/${externalId.replace(".", "/")}/`;
}

function confidenceLevel(c) {
  if (c >= 0.75) return "high";
  if (c >= 0.5) return "medium";
  return "low";
}

export default function App() {
  const [text, setText] = useState("");
  const [cve, setCve] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function handleMap() {
    const trimmedText = text.trim();
    const trimmedCve = cve.trim();
    if (!trimmedText && !trimmedCve) {
      setResult(null);
      setError("Enter an advisory description or a CVE ID first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    // A CVE ID, when present, takes priority over the free-text box.
    const body = trimmedCve ? { cve: trimmedCve } : { text: trimmedText };

    try {
      const resp = await fetch(`${API_BASE}/map`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!resp.ok) {
        let detail = `Request failed (HTTP ${resp.status}).`;
        try {
          const err = await resp.json();
          if (err.detail) {
            detail =
              typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail);
          }
        } catch {
          // response had no JSON body; keep the generic message
        }
        setError(detail);
        return;
      }

      setResult(await resp.json());
    } catch {
      setError("Could not reach the backend. Is it running on http://localhost:8000 ?");
    } finally {
      setLoading(false);
    }
  }

  const bothProvided = cve.trim() && text.trim();

  return (
    <div className="app">
      <header className="header">
        <h1>
          sparta<span className="accent">-mapper</span>
        </h1>
        <p className="tagline">
          Map a CVE or security advisory to an Aerospace Corporation{" "}
          <a href="https://sparta.aerospace.org/" target="_blank" rel="noreferrer">
            SPARTA
          </a>{" "}
          space-cyber technique.
        </p>
      </header>

      <section className="card input-card">
        <label className="field-label" htmlFor="advisory">
          Advisory / vulnerability description
        </label>
        <textarea
          id="advisory"
          className="textarea"
          rows={5}
          placeholder="e.g. An attacker with access to the ground segment intercepts and modifies telecommands before they are uplinked to the spacecraft..."
          value={text}
          onChange={(e) => setText(e.target.value)}
          disabled={loading}
        />

        <div className="divider">
          <span>or look up a CVE</span>
        </div>

        <label className="field-label" htmlFor="cve">
          CVE ID
        </label>
        <input
          id="cve"
          className="input"
          placeholder="e.g. CVE-2021-44228"
          value={cve}
          onChange={(e) => setCve(e.target.value)}
          disabled={loading}
        />

        <button className="map-button" onClick={handleMap} disabled={loading}>
          {loading ? (
            <>
              <span className="spinner" /> Mapping…
            </>
          ) : (
            "Map to SPARTA"
          )}
        </button>

        {bothProvided && (
          <p className="hint">
            A CVE ID is set — the CVE lookup takes priority over the text box.
          </p>
        )}
      </section>

      {error && <div className="card error-card">{error}</div>}

      {result && !error && result.matched && (
        <section className="card result-card">
          {result.description && (
            <div className="fetched">
              <span className="fetched-label">Fetched from NVD</span>
              <p>{result.description}</p>
            </div>
          )}

          <div className="result-head">
            <a
              className="technique-id"
              href={techniqueUrl(result.external_id)}
              target="_blank"
              rel="noreferrer"
            >
              {result.external_id}
            </a>
            <h2 className="technique-name">{result.name}</h2>
          </div>

          <div className="meta-row">
            {result.tactics && <span className="tactic-badge">{result.tactics}</span>}
            <span className={`conf-badge conf-${confidenceLevel(result.confidence)}`}>
              {Math.round(result.confidence * 100)}% confidence
            </span>
          </div>

          <div className="conf-bar-track">
            <div
              className={`conf-bar-fill conf-${confidenceLevel(result.confidence)}`}
              style={{ width: `${Math.round(result.confidence * 100)}%` }}
            />
          </div>

          <h3 className="section-h">Reasoning</h3>
          <p className="reasoning">{result.reasoning}</p>

          <h3 className="section-h">
            Countermeasures <span className="count">{result.countermeasures.length}</span>
          </h3>
          {result.countermeasures.length > 0 ? (
            <ul className="cm-list">
              {result.countermeasures.map((cm) => (
                <li key={cm.external_id}>
                  <span className="cm-id">{cm.external_id}</span>
                  <span className="cm-name">{cm.name}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">
              No countermeasures linked in the local store for this technique.
            </p>
          )}

          <a
            className="verify-link"
            href={techniqueUrl(result.external_id)}
            target="_blank"
            rel="noreferrer"
          >
            View {result.external_id} on sparta.aerospace.org →
          </a>
        </section>
      )}

      {result && !error && !result.matched && (
        <section className="card nomatch-card">
          <h2>No confident SPARTA match</h2>
          <p className="reasoning">{result.reasoning}</p>
        </section>
      )}

      <footer className="footer">
        Independent community project — not affiliated with or endorsed by The Aerospace
        Corporation. Mapping output is a starting point for analyst judgment, not an
        authoritative classification.
      </footer>
    </div>
  );
}
