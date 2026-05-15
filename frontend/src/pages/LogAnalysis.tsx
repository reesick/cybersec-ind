import { AlertCircle, AlertTriangle, CheckCircle, ChevronDown, ChevronUp, FileText, Shield, Upload } from "lucide-react";
import { useCallback, useRef, useState } from "react";
import { api } from "../api/client";

// ── Types ──────────────────────────────────────────────────────────────────

interface MatchedLine {
  line_number: number;
  content: string;
}

interface ThreatResult {
  type: string;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  match_count: number;
  matched_lines: MatchedLine[];
}

interface AnalysisResult {
  filename: string;
  total_lines: number;
  status: "clean" | "suspicious" | "malicious";
  threat_score: number;
  threats_detected: ThreatResult[];
  summary: string;
}

// ── Severity helpers ────────────────────────────────────────────────────────

const SEV_STYLE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
};

const STATUS_CONFIG = {
  clean: {
    icon: CheckCircle,
    color: "text-green-400",
    bg: "bg-green-500/10 border-green-500/30",
    label: "Clean",
  },
  suspicious: {
    icon: AlertTriangle,
    color: "text-yellow-400",
    bg: "bg-yellow-500/10 border-yellow-500/30",
    label: "Suspicious",
  },
  malicious: {
    icon: AlertCircle,
    color: "text-red-400",
    bg: "bg-red-500/10 border-red-500/30",
    label: "Malicious",
  },
};

// ── Sub-components ──────────────────────────────────────────────────────────

function ScoreRing({ score }: { score: number }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score === 0 ? "#22c55e" : score < 40 ? "#eab308" : "#ef4444";

  return (
    <svg width={96} height={96} className="rotate-[-90deg]">
      <circle cx={48} cy={48} r={radius} stroke="#334155" strokeWidth={8} fill="none" />
      <circle
        cx={48} cy={48} r={radius}
        stroke={color} strokeWidth={8} fill="none"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        className="[transition:stroke-dashoffset_0.6s_ease]"
      />
      <text
        x={48} y={54}
        textAnchor="middle"
        fill={color}
        fontSize={20}
        fontWeight="bold"
        transform="rotate(90 48 48)"
      >
        {score}
      </text>
    </svg>
  );
}

function ThreatCard({ threat }: { threat: ThreatResult }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-[#0f172a] border border-[#334155] rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded((p) => !p)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-[#1e293b] transition-colors"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${SEV_STYLE[threat.severity]}`}>
            {threat.severity.toUpperCase()}
          </span>
          <span className="text-white font-medium text-sm truncate">{threat.label}</span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <span className="text-slate-400 text-xs">{threat.match_count} match{threat.match_count !== 1 ? "es" : ""}</span>
          {expanded ? <ChevronUp size={14} className="text-slate-400" /> : <ChevronDown size={14} className="text-slate-400" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[#334155] px-4 py-3 space-y-1.5 max-h-64 overflow-y-auto">
          <p className="text-xs text-slate-500 mb-2">
            Matched lines (showing up to 20):
          </p>
          {threat.matched_lines.map((ml) => (
            <div key={ml.line_number} className="flex gap-3 font-mono text-xs">
              <span className="text-slate-600 w-10 text-right shrink-0">L{ml.line_number}</span>
              <span className="text-slate-300 break-all">{ml.content}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Sample log catalogue ────────────────────────────────────────────────────

const SAMPLES = [
  { name: "normal_access.log", label: "Normal Web Traffic", desc: "Routine HTTP requests with no threats" },
  { name: "brute_force.log", label: "Brute Force Attack", desc: "SSH & login brute-force attempts" },
  { name: "sql_injection.log", label: "SQL Injection", desc: "SQLi payloads in web requests" },
  { name: "malware_activity.log", label: "Malware Activity", desc: "Malware download, C2 callbacks, shellcode" },
  { name: "unauthorized_access.log", label: "Unauthorized Access", desc: "Directory traversal & 403s" },
  { name: "data_exfiltration.log", label: "Data Exfiltration", desc: "Large outbound transfers & DNS tunneling" },
  { name: "mixed_threats.log", label: "Mixed Threats", desc: "All five attack types combined" },
];

// ── Main page ───────────────────────────────────────────────────────────────

export default function LogAnalysis() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const analyze = useCallback(async (file: File) => {
    setLoading(true);
    setError(null);
    setResult(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await api.post<AnalysisResult>("/log-analysis/analyze", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(res.data);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? "Analysis failed. Check server logs.");
    } finally {
      setLoading(false);
    }
  }, []);

  const handleFile = useCallback(
    (file: File | undefined) => {
      if (file) analyze(file);
    },
    [analyze],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      handleFile(e.dataTransfer.files[0]);
    },
    [handleFile],
  );

  const loadSample = useCallback(
    async (name: string) => {
      setLoading(true);
      setError(null);
      setResult(null);
      try {
        const res = await api.get<string>(`/log-analysis/sample/${name}`, { responseType: "text" });
        const blob = new Blob([res.data as string], { type: "text/plain" });
        const file = new File([blob], name, { type: "text/plain" });
        await analyze(file);
      } catch {
        setError("Could not load sample file.");
        setLoading(false);
      }
    },
    [analyze],
  );

  const statusCfg = result ? STATUS_CONFIG[result.status] : null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Log File Analysis</h1>
        <p className="text-slate-400 text-sm mt-1">
          Upload a log file to detect cyber threats — brute force, SQL injection, malware, unauthorized access, and data exfiltration.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left column: upload + samples */}
        <div className="xl:col-span-1 space-y-4">
          {/* Drop zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
            className={`relative cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
              dragging
                ? "border-blue-500 bg-blue-500/10"
                : "border-[#334155] hover:border-blue-500/50 hover:bg-blue-500/5"
            }`}
          >
            <input
              ref={inputRef}
              type="file"
              accept=".log,.txt,.csv"
              aria-label="Upload log file for analysis"
              className="hidden"
              onChange={(e) => handleFile(e.target.files?.[0])}
            />
            <Upload size={28} className="mx-auto mb-3 text-slate-500" />
            <p className="text-sm text-slate-300 font-medium">Drop a log file here</p>
            <p className="text-xs text-slate-500 mt-1">or click to browse — .log, .txt, .csv</p>
          </div>

          {/* Sample catalogue */}
          <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2">
              <FileText size={14} className="text-blue-400" />
              <span className="text-sm font-semibold text-white">Sample Log Files</span>
            </div>
            <p className="text-xs text-slate-500">
              Try a pre-built sample to see the detector in action.
            </p>
            <div className="space-y-2">
              {SAMPLES.map((s) => (
                <button
                  type="button"
                  key={s.name}
                  onClick={() => loadSample(s.name)}
                  disabled={loading}
                  className="w-full text-left px-3 py-2.5 rounded-lg bg-[#0f172a] border border-[#334155] hover:border-blue-500/50 hover:bg-blue-500/5 transition-colors disabled:opacity-50"
                >
                  <div className="text-sm text-slate-200 font-medium">{s.label}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{s.desc}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right column: results */}
        <div className="xl:col-span-2 space-y-4">
          {loading && (
            <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-10 flex flex-col items-center gap-4">
              <Shield size={32} className="text-blue-400 animate-pulse" />
              <p className="text-slate-400 text-sm">Analyzing log file…</p>
            </div>
          )}

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-start gap-3">
              <AlertCircle size={18} className="text-red-400 shrink-0 mt-0.5" />
              <p className="text-red-300 text-sm">{error}</p>
            </div>
          )}

          {result && statusCfg && (
            <>
              {/* Status banner */}
              <div className={`rounded-xl border p-5 flex items-center gap-5 ${statusCfg.bg}`}>
                <ScoreRing score={result.threat_score} />
                <div className="min-w-0">
                  <div className={`text-xl font-bold ${statusCfg.color}`}>
                    {statusCfg.label}
                  </div>
                  <div className="text-sm text-slate-300 mt-0.5">{result.summary}</div>
                  <div className="flex gap-4 mt-3 text-xs text-slate-500">
                    <span>File: <span className="text-slate-300">{result.filename}</span></span>
                    <span>Lines: <span className="text-slate-300">{result.total_lines.toLocaleString()}</span></span>
                    <span>Threats: <span className="text-slate-300">{result.threats_detected.length}</span></span>
                  </div>
                </div>
              </div>

              {/* Threat breakdown */}
              {result.threats_detected.length > 0 ? (
                <div className="space-y-3">
                  <h2 className="text-white font-semibold text-sm">Detected Threats</h2>
                  {result.threats_detected.map((t) => (
                    <ThreatCard key={t.type} threat={t} />
                  ))}
                </div>
              ) : (
                <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-6 text-center">
                  <CheckCircle size={28} className="mx-auto mb-3 text-green-400" />
                  <p className="text-green-400 font-medium">No threats detected</p>
                  <p className="text-slate-500 text-xs mt-1">
                    Log file shows only normal activity patterns.
                  </p>
                </div>
              )}
            </>
          )}

          {!loading && !result && !error && (
            <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-10 flex flex-col items-center gap-4 text-center">
              <Shield size={36} className="text-slate-600" />
              <div>
                <p className="text-slate-400 text-sm font-medium">No file analyzed yet</p>
                <p className="text-slate-600 text-xs mt-1">
                  Upload a log file or select a sample on the left to begin.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
