import { useState, useEffect } from "react";
import "./App.css";

const API_URL = "http://localhost:5000/api/ip/check";
const HEALTH_URL = "http://localhost:5000/";

function validateIPv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;

    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

function isPrivateIP(ip) {
  const [a, b] = ip.split(".").map(Number);

  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

function formatDate(timestamp) {
  if (!timestamp) return "Not available";
  return new Date(timestamp * 1000).toLocaleString();
}

function getRisk(analysis) {
  if (analysis.malicious > 0) {
    return {
      risk: "HIGH",
      status: "Malicious detections",
      riskClass: "high",
    };
  }

  if (analysis.suspicious > 0) {
    return {
      risk: "MEDIUM",
      status: "Suspicious detections",
      riskClass: "medium",
    };
  }

  return {
    risk: "LOW",
    status: "No detections",
    riskClass: "low",
  };
}

function getStoredHistory() {
  try {
    const saved = localStorage.getItem("sentrix_scan_history");
    return saved ? JSON.parse(saved) : [];
  } catch {
    return [];
  }
}

function App() {
  const [ipAddress, setIpAddress] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [scanHistory, setScanHistory] = useState(getStoredHistory);
  const [backendOnline, setBackendOnline] = useState(false);

  // Save scan history whenever it changes
  useEffect(() => {
    localStorage.setItem(
      "sentrix_scan_history",
      JSON.stringify(scanHistory)
    );
  }, [scanHistory]);

  // Check backend connection
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const response = await fetch(HEALTH_URL);
        setBackendOnline(response.ok);
      } catch {
        setBackendOnline(false);
      }
    };

    checkBackend();
  }, []);

  // Generate weekly analytics from actual saved scans
  const weeklyData = Array.from({ length: 7 }, (_, index) => {
    const date = new Date();
    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() - (6 - index));

    const nextDate = new Date(date);
    nextDate.setDate(nextDate.getDate() + 1);

    const dayScans = scanHistory.filter((scan) => {
      const scanDate = new Date(scan.timestamp);
      return scanDate >= date && scanDate < nextDate;
    });

    const threats = dayScans.filter(
      (scan) => scan.analysis.malicious > 0
    ).length;

    return {
      day: date.toLocaleDateString("en-US", {
        weekday: "short",
      }),
      scans: dayScans.length,
      threats,
    };
  });

  const totalScans = scanHistory.length;

  const totalMalicious = scanHistory.filter(
    (scan) => scan.analysis.malicious > 0
  ).length;

  const latestResult = result || scanHistory[0] || null;

  const totalEngines = latestResult
    ? latestResult.analysis.malicious +
      latestResult.analysis.suspicious +
      latestResult.analysis.harmless +
      latestResult.analysis.undetected
    : 0;

  const handleCheck = async (e) => {
    e.preventDefault();

    const ip = ipAddress.trim();

    setError("");
    setResult(null);

    if (!ip) {
      setError("Please enter an IP address.");
      return;
    }

    if (!validateIPv4(ip)) {
      setError("Invalid IPv4 address. Example: 8.8.8.8");
      return;
    }

    if (isPrivateIP(ip)) {
      setError(
        "Private IP addresses cannot be checked using public VirusTotal data."
      );
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ip }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "IP scan failed.");
      }

      const analysis = {
        malicious: data.analysis?.malicious ?? 0,
        suspicious: data.analysis?.suspicious ?? 0,
        harmless: data.analysis?.harmless ?? 0,
        undetected: data.analysis?.undetected ?? 0,
      };

      const classification = getRisk(analysis);

      const scanResult = {
        id: `${Date.now()}-${Math.random()}`,
        ip: data.ip || ip,
        ...classification,
        reputation: data.reputation ?? 0,
        analysis,
        lastAnalysisDate: formatDate(data.lastAnalysisDate),
        time: new Date().toLocaleString(),
        timestamp: Date.now(),
      };

      setResult(scanResult);

      setScanHistory((previous) =>
        [scanResult, ...previous].slice(0, 100)
      );
    } catch (err) {
      setError(
        err.message || "Unable to connect to SENTRIX backend."
      );
    } finally {
      setLoading(false);
    }
  };

  const clearScan = () => {
    setIpAddress("");
    setError("");
    setResult(null);
  };

  const clearHistory = () => {
    const confirmed = window.confirm(
      "Are you sure you want to delete all saved scan history?"
    );

    if (confirmed) {
      setScanHistory([]);
      setResult(null);
    }
  };

  const malicious = latestResult?.analysis.malicious ?? 0;
  const suspicious = latestResult?.analysis.suspicious ?? 0;
  const harmless = latestResult?.analysis.harmless ?? 0;
  const undetected = latestResult?.analysis.undetected ?? 0;

  const maliciousPercent =
    totalEngines > 0 ? (malicious / totalEngines) * 100 : 0;

  const suspiciousPercent =
    totalEngines > 0 ? (suspicious / totalEngines) * 100 : 0;

  const harmlessPercent =
    totalEngines > 0 ? (harmless / totalEngines) * 100 : 0;

  const donutStyle = {
    background:
      totalEngines > 0
        ? `conic-gradient(
            #ff6279 0% ${maliciousPercent}%,
            #ffc35b ${maliciousPercent}% ${maliciousPercent + suspiciousPercent}%,
            #42e6a2 ${maliciousPercent + suspiciousPercent}% ${maliciousPercent + suspiciousPercent + harmlessPercent}%,
            #526783 ${maliciousPercent + suspiciousPercent + harmlessPercent}% 100%
          )`
        : "#263b57",
  };

  return (
    <div className="dashboard">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">◈</div>
          <h2>SENTRIX</h2>
        </div>

        <p className="menu-label">MAIN MENU</p>

        <nav className="navigation">
          <a className="nav-link active"><span>▦</span> Dashboard</a>
          <a className="nav-link"><span>⌕</span> IP Reputation</a>
          <a className="nav-link"><span>◉</span> URL Scanner</a>
          <a className="nav-link"><span>◈</span> Threat Intelligence</a>
          <a className="nav-link"><span>◷</span> Security Logs</a>
          <a className="nav-link"><span>⚙</span> Settings</a>
        </nav>

        <div className="sidebar-status">
          <span className="online-dot"></span>
          <div>
            <strong>
              {backendOnline ? "System Online" : "Backend Offline"}
            </strong>
            <small>
              {backendOnline
                ? "Backend service available"
                : "Check server connection"}
            </small>
          </div>
        </div>

        <div className="sidebar-footer">SENTRIX v1.0.0</div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
            <h1>Security Dashboard</h1>
          </div>

          <div className="topbar-right">
            <div className="notification">♧ <span></span></div>
            <div className="profile">
              <div className="avatar">A</div>
              <div>
                <strong>Administrator</strong>
                <small>Security Analyst</small>
              </div>
            </div>
          </div>
        </header>

        {/* HERO */}
        <section className="hero">
          <div className="hero-content">
            <span className="hero-tag">◈ THREAT MONITORING ACTIVE</span>
            <h2>Your Digital World,<br />Under Watch.</h2>
            <p>
              Monitor threats, investigate suspicious IP addresses
              and strengthen your digital security from one place.
            </p>
            <button
              className="hero-button"
              onClick={() =>
                document.getElementById("ip-checker")?.scrollIntoView({
                  behavior: "smooth",
                })
              }
            >
              Start New Scan →
            </button>
          </div>

          <div className="hero-visual">
            <div className="orbit orbit-one"></div>
            <div className="orbit orbit-two"></div>
            <div className="hero-shield">⬡</div>
            <span className="orbit-dot"></span>
          </div>
        </section>

        {/* STATISTICS */}
        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span>Total Scans</span>
              <span className="stat-icon cyan">⌕</span>
            </div>
            <h2>{totalScans}</h2>
            <p className="positive">Saved <span>scan records</span></p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>Malicious Scans</span>
              <span className="stat-icon red">⚠</span>
            </div>
            <h2>{totalMalicious}</h2>
            <p className="negative">Saved <span>malicious results</span></p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>Harmless Engines</span>
              <span className="stat-icon green">✓</span>
            </div>
            <h2>{latestResult ? harmless : "—"}</h2>
            <p className="positive">VirusTotal <span>latest scan</span></p>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span>Backend Status</span>
              <span className="stat-icon purple">◉</span>
            </div>
            <h2>{backendOnline ? "Online" : "Offline"}</h2>
            <p className={backendOnline ? "positive" : "negative"}>
              ● <span>Port 5000</span>
            </p>
          </div>
        </section>

        {/* ANALYTICS */}
        <section className="analytics-grid">
          <div className="panel chart-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">SECURITY ANALYTICS</p>
                <h2>Weekly Scan Activity</h2>
              </div>
              <span className="period-label">Last 7 days</span>
            </div>

            <div className="chart-legend">
              <span><i className="legend-scans"></i> Total Scans</span>
              <span><i className="legend-threats"></i> Malicious Scans</span>
            </div>

            <div className="bar-chart">
              {weeklyData.map((item) => (
                <div className="chart-column" key={item.day}>
                  <div className="bars">
                    <div
                      className="bar scans-bar"
                      style={{
                        height: `${Math.min(item.scans * 15, 100)}%`,
                      }}
                      title={`${item.scans} scans`}
                    ></div>
                    <div
                      className="bar threats-bar"
                      style={{
                        height: `${Math.min(item.threats * 15, 100)}%`,
                      }}
                      title={`${item.threats} malicious scans`}
                    ></div>
                  </div>
                  <span>{item.day}</span>
                </div>
              ))}
            </div>

            {totalScans === 0 && (
              <p className="result-description">
                Your scan activity will appear here after scanning IPs.
              </p>
            )}
          </div>

          <div className="panel risk-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">LATEST IP ANALYSIS</p>
                <h2>Risk Distribution</h2>
              </div>
            </div>

            {latestResult ? (
              <div className="risk-content">
                <div className="donut-chart" style={donutStyle}>
                  <div className="donut-inner">
                    <strong>{totalEngines}</strong>
                    <span>Engines</span>
                  </div>
                </div>

                <div className="risk-legend">
                  <div>
                    <i className="risk-high"></i>
                    <span>Malicious</span>
                    <strong>{malicious}</strong>
                  </div>
                  <div>
                    <i className="risk-medium"></i>
                    <span>Suspicious</span>
                    <strong>{suspicious}</strong>
                  </div>
                  <div>
                    <i className="risk-safe"></i>
                    <span>Harmless</span>
                    <strong>{harmless}</strong>
                  </div>
                  <div>
                    <i style={{ background: "#526783" }}></i>
                    <span>Undetected</span>
                    <strong>{undetected}</strong>
                  </div>
                </div>
              </div>
            ) : (
              <p className="result-description">
                Run an IP scan to see its latest VirusTotal analysis statistics.
              </p>
            )}
          </div>
        </section>

        {/* IP CHECKER */}
        <section className="panel checker-panel" id="ip-checker">
          <div>
            <p className="eyebrow">IP INTELLIGENCE</p>
            <h2>IP Reputation Checker</h2>
            <p>
              Enter a public IPv4 address to investigate its reputation using VirusTotal.
            </p>
          </div>

          <form onSubmit={handleCheck}>
            <input
              type="text"
              placeholder="Enter IP address (e.g. 8.8.8.8)"
              value={ipAddress}
              onChange={(e) => {
                setIpAddress(e.target.value);
                setError("");
                setResult(null);
              }}
              disabled={loading}
            />

            <button type="submit" disabled={loading}>
              {loading ? "Scanning..." : "Analyze IP →"}
            </button>
          </form>

          {error && (
            <div className="scan-error">
              <span>⚠</span> {error}
            </div>
          )}

          {loading && (
            <div className="loading-box">
              <div className="loader"></div>
              <span>Contacting VirusTotal... Please wait.</span>
            </div>
          )}

          {result && (
            <div className={`result-card result-${result.riskClass}`}>
              <div className="result-heading">
                <div>
                  <p className="eyebrow">VIRUSTOTAL SCAN RESULT</p>
                  <h3>{result.ip}</h3>
                </div>

                <span className={`result-badge ${result.riskClass}`}>
                  {result.status}
                </span>
              </div>

              <div className="result-details">
                <div>
                  <small>Risk Classification</small>
                  <strong>{result.risk}</strong>
                </div>
                <div>
                  <small>VirusTotal Reputation</small>
                  <strong>{result.reputation}</strong>
                </div>
                <div>
                  <small>Last Analysis</small>
                  <strong>{result.lastAnalysisDate}</strong>
                </div>
                <div>
                  <small>Scan Time</small>
                  <strong>{result.time}</strong>
                </div>
              </div>

              <div className="result-details">
                <div>
                  <small>Malicious</small>
                  <strong>{result.analysis.malicious}</strong>
                </div>
                <div>
                  <small>Suspicious</small>
                  <strong>{result.analysis.suspicious}</strong>
                </div>
                <div>
                  <small>Harmless</small>
                  <strong>{result.analysis.harmless}</strong>
                </div>
                <div>
                  <small>Undetected</small>
                  <strong>{result.analysis.undetected}</strong>
                </div>
              </div>

              <p className="result-description">
                These results represent VirusTotal's latest available
                engine analysis. Zero detections do not guarantee that
                an IP address is completely safe.
              </p>

              <div className="demo-notice">
                LIVE DATA · Source: VirusTotal API
              </div>

              <button
                type="button"
                className="clear-button"
                onClick={clearScan}
              >
                Clear Result
              </button>
            </div>
          )}
        </section>

        {/* RECENT SCANS */}
        <section className="panel history-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">MONITORING ACTIVITY</p>
              <h2>Recent Scan History</h2>
            </div>

            <button
              type="button"
              className="clear-button"
              onClick={clearHistory}
              disabled={scanHistory.length === 0}
            >
              Clear History
            </button>
          </div>

          <div className="scan-table">
            <div className="scan-row scan-header">
              <span>IP ADDRESS</span>
              <span>SCAN TYPE</span>
              <span>RISK LEVEL</span>
              <span>STATUS</span>
            </div>

            {scanHistory.length === 0 ? (
              <div className="scan-row">
                <span>No scans yet</span>
                <span>—</span>
                <span>—</span>
                <span>Waiting</span>
              </div>
            ) : (
              scanHistory.map((scan) => (
                <div className="scan-row" key={scan.id}>
                  <span>{scan.ip}</span>
                  <span>IP Reputation</span>
                  <span className={`risk-text ${scan.riskClass}`}>
                    {scan.risk}
                  </span>
                  <span className={`status-text ${scan.riskClass}`}>
                    {scan.status}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>

        <footer className="footer">
          SENTRIX © 2026 · Your Digital World, Under Watch.
          <span>Threat intelligence powered by VirusTotal.</span>
        </footer>
      </main>
    </div>
  );
}

export default App;