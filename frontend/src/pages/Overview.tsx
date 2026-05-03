import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Shield, TrendingUp } from "lucide-react";
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
import { api, ForecastSummary, ValidationMetrics } from "../api/client";
import Hint from "../components/Hint";

function KpiCard({
  icon: Icon,
  label,
  value,
  sub,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  sub?: string;
  color: string;
}) {
  return (
    <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-slate-400 text-sm">{label}</span>
        <span className={`p-2 rounded-lg ${color}`}>
          <Icon size={16} />
        </span>
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </div>
  );
}

const METRIC_DESCRIPTIONS: Record<string, { full: string; meaning: string }> = {
  RSE: {
    full: "Relative Squared Error",
    meaning: "Error relative to a naive mean predictor — closer to 0 is better",
  },
  RAE: {
    full: "Relative Absolute Error",
    meaning: "Average prediction error relative to baseline — closer to 0 is better",
  },
  RMSE: {
    full: "Root Mean Square Error",
    meaning: "Average prediction error in original units — lower is better",
  },
  R2: {
    full: "R² Score",
    meaning: "How much variance the model explains — closer to 1.0 is better",
  },
};

export default function Overview() {
  const { data: summary } = useQuery<ForecastSummary[]>({
    queryKey: ["forecast-summary"],
    queryFn: () => api.get("/forecast/summary").then((r) => r.data),
  });

  const { data: validation } = useQuery<ValidationMetrics>({
    queryKey: ["validation"],
    queryFn: () => api.get("/metrics/validation").then((r) => r.data),
  });

  const { data: nodes } = useQuery<{ threats: string[]; pats: string[] }>({
    queryKey: ["nodes"],
    queryFn: () => api.get("/forecast/nodes").then((r) => r.data),
  });

  const threats = summary?.filter((s) => s.type === "threat") ?? [];
  const topThreats = [...threats]
    .sort((a, b) => b.avg_pred - a.avg_pred)
    .slice(0, 8)
    .map((t) => ({ ...t, label: t.node }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Overview</h1>
        <p className="text-slate-400 text-sm mt-1">
          AI-powered cyber threat forecasting using the B-MTGNN model — predicting
          research trends across 26 threats and 97 defense technologies from
          2023 to 2025.
        </p>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          icon={AlertTriangle}
          label="Cyber Threats Tracked"
          value={nodes?.threats.length ?? "—"}
          sub="attack types monitored"
          color="bg-red-500/20 text-red-400"
        />
        <KpiCard
          icon={Shield}
          label="Defense Technologies"
          value={nodes?.pats.length ?? "—"}
          sub="protection methods tracked"
          color="bg-blue-500/20 text-blue-400"
        />
        <KpiCard
          icon={TrendingUp}
          label="Model Accuracy (R²)"
          value={validation ? validation.R2.toFixed(4) : "—"}
          sub="1.0 = perfect, 0 = random"
          color="bg-green-500/20 text-green-400"
        />
        <KpiCard
          icon={Activity}
          label="Avg Prediction Error"
          value={validation ? validation.RMSE.toFixed(1) : "—"}
          sub="papers/month (RMSE)"
          color="bg-purple-500/20 text-purple-400"
        />
      </div>

      {/* Bar chart */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 space-y-3">
        <div>
          <h2 className="text-white font-semibold">
            Most Researched Cyber Threats (Predicted 2023–2025)
          </h2>
          <p className="text-slate-400 text-xs mt-0.5">
            Average number of academic publications per month predicted to
            mention each threat
          </p>
        </div>
        <Hint text="Longer bars indicate threats attracting higher research attention. This does not directly measure real-world attack frequency — it reflects how much the academic and security community is writing about each threat." />
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={topThreats} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis
              type="number"
              tick={{ fill: "#94a3b8", fontSize: 12 }}
              label={{
                value: "Avg monthly papers predicted",
                position: "insideBottom",
                offset: -2,
                fill: "#64748b",
                fontSize: 11,
              }}
            />
            <YAxis
              type="category"
              dataKey="label"
              width={140}
              tick={{ fill: "#94a3b8", fontSize: 11 }}
            />
            <Tooltip
              contentStyle={{
                background: "#1e293b",
                border: "1px solid #334155",
                borderRadius: 8,
              }}
              labelStyle={{ color: "#e2e8f0" }}
              itemStyle={{ color: "#94a3b8" }}
              formatter={(val: number) => [
                `${val.toFixed(2)} papers/month`,
                "Avg Predicted Volume",
              ]}
            />
            <Legend
              verticalAlign="top"
              formatter={() => "Avg predicted papers/month"}
            />
            <Bar dataKey="avg_pred" name="Avg predicted papers/month" radius={[0, 4, 4, 0]}>
              {topThreats.map((_, i) => (
                <Cell
                  key={i}
                  fill={i === 0 ? "#ef4444" : i < 3 ? "#f97316" : "#3b82f6"}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Model accuracy cards */}
      {validation && (
        <div className="space-y-3">
          <div>
            <h2 className="text-white font-semibold">Model Performance Metrics</h2>
            <p className="text-slate-400 text-xs mt-0.5">
              How accurately the AI model predicted known data — measured across
              all 123 threat and defense technology time series
            </p>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {(Object.keys(METRIC_DESCRIPTIONS) as (keyof ValidationMetrics)[]).map(
              (k) => {
                const info = METRIC_DESCRIPTIONS[k as string];
                return (
                  <div
                    key={k}
                    className="bg-[#1e293b] border border-[#334155] rounded-xl p-4"
                  >
                    <div className="text-xs text-blue-400 font-medium mb-1">
                      {k}
                    </div>
                    <div className="text-slate-300 text-xs mb-2">{info.full}</div>
                    <div className="text-2xl font-bold text-white">
                      {validation[k] < 1
                        ? validation[k].toFixed(4)
                        : validation[k].toFixed(2)}
                    </div>
                    <div className="text-xs text-slate-500 mt-2 leading-relaxed">
                      {info.meaning}
                    </div>
                  </div>
                );
              }
            )}
          </div>
        </div>
      )}
    </div>
  );
}
