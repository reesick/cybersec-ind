import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, ForecastPoint } from "../api/client";
import Hint from "../components/Hint";

function NodeList({
  label,
  nodes,
  selected,
  onSelect,
  color,
}: {
  label: string;
  nodes: string[];
  selected: string;
  onSelect: (n: string) => void;
  color: string;
}) {
  const [search, setSearch] = useState("");
  const filtered = nodes.filter((n) =>
    n.toLowerCase().includes(search.toLowerCase())
  );
  return (
    <div className="flex flex-col h-full">
      <div className={`text-xs font-semibold uppercase tracking-wider mb-2 ${color}`}>
        {label}
      </div>
      <input
        type="text"
        placeholder="Search…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="mb-2 px-3 py-1.5 text-sm bg-[#0f172a] border border-[#334155] rounded-lg text-slate-300 placeholder-slate-600 outline-none"
      />
      <div className="flex-1 overflow-y-auto space-y-0.5">
        {filtered.map((n) => (
          <button
            key={n}
            onClick={() => onSelect(n)}
            className={`w-full text-left px-3 py-1.5 rounded-lg text-sm transition-colors ${
              selected === n
                ? "bg-blue-600/20 text-blue-400"
                : "text-slate-400 hover:bg-slate-700/40 hover:text-slate-200"
            }`}
          >
            {n}
          </button>
        ))}
      </div>
    </div>
  );
}

const CustomTooltip = ({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { name: string; value: number }[];
  label?: string;
}) => {
  if (!active || !payload) return null;
  const pred = payload.find((p) => p.name === "Predicted Volume");
  const ciLower = payload.find((p) => p.name === "CI Floor");
  const ciWidth = payload.find((p) => p.name === "ciWidth");
  const upper =
    ciLower && ciWidth ? ciLower.value + ciWidth.value : null;
  return (
    <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-3 text-xs space-y-1">
      <div className="text-slate-400 mb-1">{label}</div>
      {pred && (
        <div className="text-blue-400 font-medium">
          Predicted: {pred.value.toFixed(3)} papers/month
        </div>
      )}
      {ciLower && upper !== null && (
        <div className="text-slate-400">
          Uncertainty range: {ciLower.value.toFixed(3)} – {upper.toFixed(3)}
        </div>
      )}
    </div>
  );
};

export default function Forecast() {
  const [selectedNode, setSelectedNode] = useState("DDoS");
  const [year, setYear] = useState<number | undefined>(undefined);

  const { data: nodes } = useQuery<{ threats: string[]; pats: string[] }>({
    queryKey: ["nodes"],
    queryFn: () => api.get("/forecast/nodes").then((r) => r.data),
  });

  // Fetch all data for the selected node (no year filter) to derive available years
  const { data: allNodeData } = useQuery<ForecastPoint[]>({
    queryKey: ["forecast-all", selectedNode],
    queryFn: () =>
      api.get("/forecast/", { params: { node: selectedNode } }).then((r) => r.data),
    enabled: !!selectedNode,
  });

  const availableYears = allNodeData
    ? [...new Set(allNodeData.map((d) => new Date(d.month).getFullYear()))].sort()
    : [];

  const { data: rawData, isLoading } = useQuery<ForecastPoint[]>({
    queryKey: ["forecast", selectedNode, year],
    queryFn: () =>
      api
        .get("/forecast/", { params: { node: selectedNode, year } })
        .then((r) => r.data),
    enabled: !!selectedNode,
  });

  const isDefenseTech = nodes?.pats.includes(selectedNode);

  const chartData = rawData?.map((d) => ({
    month: d.month.slice(0, 7),
    "Predicted Volume": +d.pred.toFixed(3),
    "CI Floor": +d.ci_lower.toFixed(3),
    ciWidth: +(Math.max(0, d.ci_upper - d.ci_lower)).toFixed(3),
  }));

  return (
    <div className="flex gap-4 h-[calc(100vh-3rem)]">
      {/* Sidebar */}
      <div className="w-52 shrink-0 bg-[#1e293b] border border-[#334155] rounded-xl p-4 flex flex-col gap-4 overflow-hidden">
        <NodeList
          label="Cyber Threats"
          nodes={nodes?.threats ?? []}
          selected={selectedNode}
          onSelect={setSelectedNode}
          color="text-red-400"
        />
        <div className="border-t border-[#334155]" />
        <NodeList
          label="Defense Technologies"
          nodes={nodes?.pats ?? []}
          selected={selectedNode}
          onSelect={setSelectedNode}
          color="text-blue-400"
        />
      </div>

      {/* Chart */}
      <div className="flex-1 bg-[#1e293b] border border-[#334155] rounded-xl p-5 flex flex-col gap-3 overflow-hidden">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-white font-bold text-lg">{selectedNode}</h2>
              <span
                className={`text-xs px-2 py-0.5 rounded-full ${
                  isDefenseTech
                    ? "bg-blue-500/20 text-blue-400"
                    : "bg-red-500/20 text-red-400"
                }`}
              >
                {isDefenseTech ? "Defense Technology" : "Cyber Threat"}
              </span>
            </div>
            <p className="text-slate-400 text-xs mt-0.5">
              Predicted monthly research publications
              {availableYears.length >= 2
                ? ` · ${availableYears[0]}–${availableYears[availableYears.length - 1]}`
                : ""}
            </p>
          </div>
          <div className="flex gap-2">
            {[undefined, ...availableYears].map((y) => (
              <button
                key={y ?? "all"}
                onClick={() => setYear(y)}
                className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                  year === y
                    ? "bg-blue-600 text-white"
                    : "bg-[#0f172a] text-slate-400 hover:text-white border border-[#334155]"
                }`}
              >
                {y ?? "All"}
              </button>
            ))}
          </div>
        </div>

        <Hint text="The blue line shows how many academic papers per month the model predicts will mention this topic. The shaded band is the 95% uncertainty range — wider bands mean the model is less certain about that period. Generated using Bayesian Monte Carlo dropout." />

        {isLoading ? (
          <div className="flex-1 flex items-center justify-center text-slate-500">
            Loading…
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="month"
                tick={{ fill: "#94a3b8", fontSize: 11 }}
                interval="preserveStartEnd"
                label={{
                  value: "Month",
                  position: "insideBottomRight",
                  offset: -10,
                  fill: "#64748b",
                  fontSize: 11,
                }}
              />
              <YAxis
                tick={{ fill: "#94a3b8", fontSize: 11 }}
                label={{
                  value: "Papers / month",
                  angle: -90,
                  position: "insideLeft",
                  offset: 10,
                  fill: "#64748b",
                  fontSize: 11,
                }}
              />
              <Tooltip content={<CustomTooltip />} />
              <Legend
                verticalAlign="top"
                formatter={(val) => {
                  if (val === "Predicted Volume") return "Predicted volume (papers/month)";
                  if (val === "CI Floor") return "95% confidence band";
                  return null;
                }}
              />
              <Area
                type="monotone"
                dataKey="CI Floor"
                stackId="ci"
                stroke="none"
                fill="transparent"
                legendType="none"
              />
              <Area
                type="monotone"
                dataKey="ciWidth"
                stackId="ci"
                stroke="none"
                fill="rgba(59,130,246,0.15)"
                name="95% Confidence Band"
                legendType="square"
              />
              <Line
                type="monotone"
                dataKey="Predicted Volume"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
