import {
  Activity,
  BarChart2,
  GitBranch,
  Home,
  Images,
  Lightbulb,
  Network,
  ScanSearch,
} from "lucide-react";
import { NavLink } from "react-router-dom";

const NAV = [
  { to: "/", icon: Home, label: "Overview" },
  { to: "/forecast", icon: BarChart2, label: "Forecast" },
  { to: "/gap", icon: GitBranch, label: "Gap Analysis" },
  { to: "/graph", icon: Network, label: "Threat Graph" },
  { to: "/atc", icon: Lightbulb, label: "Lifecycle & Recs" },
  { to: "/gallery", icon: Images, label: "Trend Gallery" },
  { to: "/metrics", icon: Activity, label: "Model Metrics" },
  { to: "/log-analysis", icon: ScanSearch, label: "Log Analysis" },
];

export default function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-screen w-56 bg-[#1e293b] border-r border-[#334155] flex flex-col z-10">
      <div className="px-4 py-5 border-b border-[#334155]">
        <span className="text-blue-400 font-bold text-lg tracking-tight">
          Cyber<span className="text-white">Foresight</span>
        </span>
      </div>
      <nav className="flex-1 py-4 space-y-1 px-2">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                isActive
                  ? "bg-blue-600/20 text-blue-400 font-medium"
                  : "text-slate-400 hover:bg-slate-700/50 hover:text-slate-200"
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-[#334155] text-xs text-slate-500">
        B-MTGNN | 2025-2027
      </div>
    </aside>
  );
}
