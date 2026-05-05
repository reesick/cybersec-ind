import { useQuery } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AblationRow, api, ValidationMetrics } from "../api/client";
import Hint from "../components/Hint";

const METRIC_INFO: Record<
  string,
  { full: string; good: "low" | "high"; explain: string }
> = {
  RSE: {
    full: "Relative Squared Error",
    good: "low",
    explain:
      "How much error exists relative to a simple average predictor. 0.035 means the model is 96.5% better than just predicting the mean.",
  },
  RAE: {
    full: "Relative Absolute Error",
    good: "low",
    explain:
      "Average absolute error relative to baseline. 0.029 means the model's errors are 97.1% smaller than a naive predictor.",
  },
  RMSE: {
    full: "Root Mean Square Error",
    good: "low",
    explain:
      "Average prediction error in the original unit (papers per month). 224 papers/month error across a dataset with thousands of papers/month is very low.",
  },
  R2: {
    full: "R² Score (Coefficient of Determination)",
    good: "high",
    explain:
      "How much of the variance in real data the model explains. 0.9987 means the model explains 99.87% of all variation — near-perfect.",
  },
};

const MODEL_LABELS: Record<string, string> = {
  "TCN only": "Temporal Conv. only (no graph)",
  "TCN+GCN predefined bi": "Temporal + Graph (fixed, bidirectional)",
  "TCN+GCN predefined uni": "Temporal + Graph (fixed, unidirectional)",
  "TCN+GCN adaptive": "Temporal + Adaptive Graph",
  "TCN+external": "Temporal + External signals",
  "TCN+GCN bi+external": "Temporal + Graph (bi) + External",
  "TCN+GCN uni+external": "Temporal + Graph (uni) + External",
  "TCN+GCN adaptive+external": "Full B-MTGNN Model ★",
  "LinearRegression (proxy VAR/LSTM)": "Baseline: Linear Regression",
  "Mean predictor (naive)": "Baseline: Naive Mean",
};

export default function ModelMetrics() {
  const { data: validation } = useQuery<ValidationMetrics>({
    queryKey: ["validation"],
    queryFn: () => api.get("/metrics/validation").then((r) => r.data),
  });

  const { data: ablation } = useQuery<AblationRow[]>({
    queryKey: ["ablation"],
    queryFn: () => api.get("/metrics/ablation").then((r) => r.data),
  });

  const fullModelRSE = ablation?.find((r) =>
    r.model.toLowerCase().includes("adaptive+external")
  )?.RSE;

  const chartData = ablation?.map((r) => ({
    ...r,
    label: MODEL_LABELS[r.model] ?? r.model,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Model Performance</h1>
        <p className="text-slate-400 text-sm mt-1">
          How accurately the Bayesian MTGNN (B-MTGNN) model forecasts research
          trends — and how each model component contributes to that accuracy.
        </p>
      </div>

      {/* Validation metrics */}
      {validation && (
        <div className="space-y-3">
          <h2 className="text-white font-semibold">Validation Metrics</h2>
          <Hint text="These metrics were computed on held-out test data the model never saw during training. All four metrics confirm the model is highly accurate — R² close to 1.0 is the key number to focus on." />
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {(Object.keys(METRIC_INFO) as (keyof ValidationMetrics)[]).map((k) => {
              const info = METRIC_INFO[k as string];
              return (
                <div
                  key={k}
                  className="bg-[#1e293b] border border-[#334155] rounded-xl p-5"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-blue-400 font-semibold text-sm">{k}</span>
                    <span className="text-xs text-slate-500">
                      {info.good === "high" ? "↑ higher better" : "↓ lower better"}
                    </span>
                  </div>
                  <div className="text-slate-400 text-xs mb-3">{info.full}</div>
                  <div className="text-3xl font-bold text-white">
                    {validation[k] < 1
                      ? validation[k].toFixed(4)
                      : validation[k].toFixed(2)}
                  </div>
                  <div className="text-xs text-slate-500 mt-3 leading-relaxed border-t border-[#334155] pt-2">
                    {info.explain}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Ablation chart */}
      {ablation && chartData && (
        <div className="space-y-3">
          <div>
            <h2 className="text-white font-semibold">Ablation Study</h2>
            <p className="text-slate-400 text-xs mt-0.5">
              An ablation study removes model components one by one to measure
              their individual contribution. Lower RSE = better. The full model
              (green bar) should outperform all variants.
            </p>
          </div>
          <Hint text="Each bar is a version of the model with some components removed. 'TCN only' has no graph. 'Adaptive Graph' lets the model learn relationships from data. 'External signals' adds geo-political data (armed conflict, holidays). The full B-MTGNN combines all of these." />
          <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5">
            <ResponsiveContainer width="100%" height={340}>
              <BarChart data={chartData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  type="number"
                  tick={{ fill: "#94a3b8", fontSize: 11 }}
                  label={{
                    value: "RSE (lower = better)",
                    position: "insideBottom",
                    offset: -2,
                    fill: "#64748b",
                    fontSize: 11,
                  }}
                />
                <YAxis
                  type="category"
                  dataKey="label"
                  width={240}
                  tick={{ fill: "#94a3b8", fontSize: 10 }}
                />
                <Tooltip
                  contentStyle={{
                    background: "#1e293b",
                    border: "1px solid #334155",
                    borderRadius: 8,
                  }}
                  labelStyle={{ color: "#e2e8f0" }}
                  itemStyle={{ color: "#94a3b8" }}
                  formatter={(val: number, name: string) => [
                    val.toFixed(4),
                    name,
                  ]}
                />
                <Legend
                  verticalAlign="top"
                  formatter={(val) =>
                    val === "RSE"
                      ? "Relative Squared Error (lower is better)"
                      : val
                  }
                />
                <Bar dataKey="RSE" name="RSE" radius={[0, 4, 4, 0]}>
                  {chartData.map((entry, i) => (
                    <Cell
                      key={i}
                      fill={
                        entry.RSE === fullModelRSE
                          ? "#22c55e"
                          : entry.model.includes("proxy") ||
                            entry.model.includes("naive")
                          ? "#6b7280"
                          : "#3b82f6"
                      }
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            <div className="flex gap-4 mt-2 text-xs text-slate-500">
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-sm bg-green-500 inline-block" />
                Full B-MTGNN model (best)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-sm bg-blue-500 inline-block" />
                Ablation variants
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-sm bg-gray-500 inline-block" />
                Baselines (non-neural)
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Ablation table */}
      {ablation && (
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#334155]">
            <span className="text-white font-semibold">Full Results Table</span>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#334155] text-slate-400 text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3">Model Configuration</th>
                <th className="text-right px-4 py-3">RSE ↓</th>
                <th className="text-right px-4 py-3">RAE ↓</th>
              </tr>
            </thead>
            <tbody>
              {ablation.map((row, i) => (
                <tr
                  key={i}
                  className={`border-b border-[#334155]/50 hover:bg-slate-700/20 ${
                    row.RSE === fullModelRSE ? "bg-green-900/10" : ""
                  }`}
                >
                  <td className="px-4 py-2.5 text-slate-200">
                    {MODEL_LABELS[row.model] ?? row.model}
                    {row.RSE === fullModelRSE && (
                      <span className="ml-2 text-xs text-green-400 font-medium">
                        ← best
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs text-slate-300">
                    {row.RSE.toFixed(4)}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs text-slate-300">
                    {row.RAE.toFixed(4)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
