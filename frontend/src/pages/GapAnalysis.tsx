import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, GapRow } from "../api/client";
import Hint from "../components/Hint";

const CATEGORY_MAP: Record<string, { label: string; color: string; desc: string }> = {
  ONG: {
    label: "Ongoing Gap",
    color: "bg-yellow-500/20 text-yellow-400",
    desc: "Defense research persistently lags behind the threat",
  },
  OWG: {
    label: "Growing Gap",
    color: "bg-orange-500/20 text-orange-400",
    desc: "Gap is actively widening — defense falling further behind",
  },
  SNG: {
    label: "Balanced",
    color: "bg-green-500/20 text-green-400",
    desc: "Defense research is keeping pace with the threat",
  },
  SWG: {
    label: "Critical Gap",
    color: "bg-red-500/20 text-red-400",
    desc: "Significant and widening gap — highest investment priority",
  },
};

function gapCellColor(val: number) {
  const abs = Math.abs(val);
  if (val > 0) return "bg-green-900/40 text-green-300";
  if (abs < 0.1) return "bg-slate-700 text-slate-300";
  if (abs < 0.25) return "bg-yellow-900/50 text-yellow-300";
  return "bg-red-900/50 text-red-300";
}

export default function GapAnalysis() {
  const [category, setCategory] = useState<string>("all");
  const [sortBy, setSortBy] = useState("gap_magnitude_2027");

  const { data: categories } = useQuery<string[]>({
    queryKey: ["gap-categories"],
    queryFn: () => api.get("/gap/categories").then((r) => r.data),
  });

  const { data: rows, isLoading } = useQuery<GapRow[]>({
    queryKey: ["gap", category, sortBy],
    queryFn: () =>
      api
        .get("/gap/", {
          params: {
            category: category === "all" ? undefined : category,
            sort_by: sortBy,
            limit: 200,
          },
        })
        .then((r) => r.data),
  });

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-white">Research Gap Analysis</h1>
        <p className="text-slate-400 text-sm mt-1">
          Where is defense research falling behind? Each row compares the
          growth of a cyber threat against its corresponding defense technology.
        </p>
      </div>

      <Hint text="A negative gap value means the threat is being researched more than the defense technology — i.e. attackers are ahead of defenders in the literature. A larger negative number = higher urgency for investment. Positive values mean defense is keeping up or leading." />

      {/* Category legend */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(CATEGORY_MAP).map(([code, info]) => (
          <div
            key={code}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-transparent ${info.color}`}
            title={info.desc}
          >
            <span className="font-semibold">{info.label}</span>
            <span className="text-slate-500 hidden sm:inline">— {info.desc}</span>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setCategory("all")}
            className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${
              category === "all"
                ? "bg-blue-600 text-white"
                : "bg-[#1e293b] border border-[#334155] text-slate-400 hover:text-white"
            }`}
          >
            All
          </button>
          {(categories ?? []).map((c) => (
            <button
              key={c}
              onClick={() => setCategory(c)}
              className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${
                category === c
                  ? "bg-blue-600 text-white"
                  : "bg-[#1e293b] border border-[#334155] text-slate-400 hover:text-white"
              }`}
            >
              {CATEGORY_MAP[c]?.label ?? c}
            </button>
          ))}
        </div>
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          className="ml-auto bg-[#1e293b] border border-[#334155] text-slate-300 text-sm rounded-lg px-3 py-1.5 outline-none"
        >
          <option value="gap_magnitude_2027">Sort: Priority Score (2027)</option>
          <option value="gap_2025">Sort: Gap in 2025</option>
          <option value="gap_2026">Sort: Gap in 2026</option>
          <option value="gap_2027">Sort: Gap in 2027</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#334155] text-slate-400 text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3">Cyber Threat</th>
                <th className="text-left px-4 py-3">Defense Technology</th>
                <th className="text-left px-4 py-3">Status</th>
                <th
                  className="text-center px-4 py-3"
                  title="Positive = defense ahead, negative = threat ahead"
                >
                  Gap 2025
                </th>
                <th className="text-center px-4 py-3">Gap 2026</th>
                <th className="text-center px-4 py-3">Gap 2027</th>
                <th
                  className="text-center px-4 py-3"
                  title="Higher = more urgent to address"
                >
                  Priority Score
                </th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="text-center py-10 text-slate-500">
                    Loading…
                  </td>
                </tr>
              ) : (
                rows?.map((row, i) => {
                  const catInfo = CATEGORY_MAP[row.category];
                  return (
                    <tr
                      key={i}
                      className="border-b border-[#334155]/50 hover:bg-slate-700/20 transition-colors"
                    >
                      <td className="px-4 py-2.5 text-red-400 font-medium">
                        {row.threat}
                      </td>
                      <td className="px-4 py-2.5 text-blue-400">{row.pat}</td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`px-2 py-0.5 rounded-full text-xs ${catInfo?.color ?? "bg-slate-700 text-slate-300"}`}
                          title={catInfo?.desc}
                        >
                          {catInfo?.label ?? row.category}
                        </span>
                      </td>
                      {(["gap_2025", "gap_2026", "gap_2027"] as const).map((k) => (
                        <td key={k} className="px-4 py-2.5 text-center">
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-mono ${gapCellColor(row[k])}`}
                          >
                            {row[k].toFixed(3)}
                          </span>
                        </td>
                      ))}
                      <td className="px-4 py-2.5 text-center text-white font-mono text-xs font-semibold">
                        {row.gap_magnitude_2027.toFixed(3)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {rows && (
          <div className="px-4 py-2 border-t border-[#334155] text-xs text-slate-500 flex gap-4">
            <span>{rows.length} threat–defense pairs shown</span>
            <span>
              <span className="text-red-400">Red cell</span> = large deficit ·{" "}
              <span className="text-yellow-400">Yellow</span> = moderate ·{" "}
              <span className="text-green-400">Green</span> = defense ahead
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
