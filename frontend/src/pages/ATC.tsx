import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, AtcRow } from "../api/client";
import Hint from "../components/Hint";

const PHASE_INFO: Record<string, { color: string; desc: string }> = {
  Growth: {
    color: "bg-blue-500/20 text-blue-400",
    desc: "Rapidly gaining research attention — active area of development",
  },
  "Maturity/Stability": {
    color: "bg-green-500/20 text-green-400",
    desc: "Well-established technology — research output is stable",
  },
  Trough: {
    color: "bg-purple-500/20 text-purple-400",
    desc: "Research interest temporarily declining — may be consolidating",
  },
  Decline: {
    color: "bg-red-500/20 text-red-400",
    desc: "Research output falling — technology may be losing relevance",
  },
};

export default function ATC() {
  const [activePhase, setActivePhase] = useState<string>("all");

  const { data: atcRows } = useQuery<AtcRow[]>({
    queryKey: ["atc"],
    queryFn: () => api.get("/metrics/atc").then((r) => r.data),
  });

  const phases = atcRows ? [...new Set(atcRows.map((r) => r.phase))].sort() : [];

  const filtered =
    activePhase === "all"
      ? atcRows
      : atcRows?.filter((r) => r.phase === activePhase);

  const phaseCounts = phases.reduce<Record<string, number>>((acc, p) => {
    acc[p] = atcRows?.filter((r) => r.phase === p).length ?? 0;
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">
          Technology Lifecycle & Recommendations
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          The Alleviation Technologies Cycle (ATC) classifies each defense
          technology by its current research maturity — similar to a technology
          hype cycle. Use this to understand where to focus investment.
        </p>
      </div>

      <Hint text="'Growth' technologies are rapidly emerging and worth investing in early. 'Maturity/Stability' technologies are proven and widely adopted. 'Trough' technologies are temporarily overlooked but may resurge. The slope value shows the rate of change in monthly publications." />

      {/* Phase summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {phases.map((p) => {
          const info = PHASE_INFO[p] ?? { color: "bg-slate-700 text-slate-300", desc: "" };
          return (
            <button
              key={p}
              onClick={() => setActivePhase(activePhase === p ? "all" : p)}
              className={`text-left p-4 rounded-xl border transition-all ${
                activePhase === p
                  ? "border-blue-500 bg-blue-600/10"
                  : "border-[#334155] bg-[#1e293b] hover:border-slate-500"
              }`}
            >
              <span className={`text-xs px-2 py-0.5 rounded-full ${info.color}`}>
                {p}
              </span>
              <div className="text-2xl font-bold text-white mt-2">
                {phaseCounts[p]}
              </div>
              <div className="text-xs text-slate-500 mt-1">{info.desc}</div>
            </button>
          );
        })}
      </div>

      {/* ATC diagram */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-4">
        <div className="mb-2">
          <h2 className="text-white font-semibold">ATC Diagram</h2>
          <p className="text-slate-400 text-xs mt-0.5">
            Each dot represents a defense technology plotted by its lifecycle
            phase. Position on the curve indicates research maturity.
          </p>
        </div>
        <img
          src="/api/outputs/atc_diagram.png"
          alt="Alleviation Technologies Cycle Diagram"
          className="max-w-full rounded-lg"
          onError={(e) => {
            (e.target as HTMLImageElement).parentElement!.innerHTML =
              '<p class="text-slate-500 text-sm py-4">Diagram not available — run the pipeline first.</p>';
          }}
        />
      </div>

      {/* Investment recommendations */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-4">
        <div className="flex items-center justify-between mb-2">
          <div>
            <h2 className="text-white font-semibold">Investment Recommendations</h2>
            <p className="text-slate-400 text-xs mt-0.5">
              Model-generated investment priorities based on gap analysis and
              forecast trajectories
            </p>
          </div>
          <a
            href="/api/outputs/investment_recommendations.pdf"
            target="_blank"
            rel="noreferrer"
            className="text-xs text-blue-400 hover:underline shrink-0"
          >
            Open full PDF ↗
          </a>
        </div>
        <iframe
          src="/api/outputs/investment_recommendations.pdf"
          className="w-full h-96 rounded-lg border border-[#334155]"
          title="Investment Recommendations"
        />
      </div>

      {/* PAT phase table */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-[#334155] flex items-center gap-2 flex-wrap">
          <span className="text-white font-semibold mr-2">
            Defense Technology Phases
          </span>
          {["all", ...phases].map((p) => (
            <button
              key={p}
              onClick={() => setActivePhase(p)}
              className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                activePhase === p
                  ? "bg-blue-600 text-white"
                  : "bg-[#0f172a] border border-[#334155] text-slate-400 hover:text-white"
              }`}
            >
              {p === "all" ? "All" : PHASE_INFO[p] ? p : p}
            </button>
          ))}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#334155] text-slate-400 text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3">Defense Technology</th>
                <th className="text-left px-4 py-3">Lifecycle Phase</th>
                <th className="text-right px-4 py-3" title="Rate of change in publications per month">
                  Growth Rate
                </th>
                <th className="text-left px-4 py-3">Phase Meaning</th>
              </tr>
            </thead>
            <tbody>
              {filtered?.map((row, i) => {
                const info = PHASE_INFO[row.phase] ?? {
                  color: "bg-slate-700 text-slate-300",
                  desc: "",
                };
                return (
                  <tr
                    key={i}
                    className="border-b border-[#334155]/50 hover:bg-slate-700/20"
                  >
                    <td className="px-4 py-2.5 text-blue-400 font-medium">
                      {row.pat}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded-full text-xs ${info.color}`}>
                        {row.phase}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-xs text-slate-300">
                      {row.slope > 0 ? "+" : ""}
                      {row.slope.toFixed(3)}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 text-xs">
                      {info.desc}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="px-4 py-2 border-t border-[#334155] text-xs text-slate-500">
          Growth Rate = monthly rate of change in academic publications ·
          Positive = growing interest · Negative = declining interest
        </div>
      </div>
    </div>
  );
}
