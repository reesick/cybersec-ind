import { useState } from "react";
import { X } from "lucide-react";
import Hint from "../components/Hint";

const THREATS = [
  "Account_Hijacking", "Adversarial_Attack", "APT", "Backdoor", "Botnet",
  "Brute_Force_Attack", "Cryptojacking", "Data_Poisoning", "DDoS", "Deepfake",
  "Disinformation", "DNS_Spoofing", "Dropper", "Insider_Threat",
  "IoT_Device_Attack", "Malware", "MITM", "Password_Attack", "Phishing",
  "Ransomware", "Session_Hijacking", "Supply_Chain_Attack", "Targeted_Attack",
  "Trojan", "Vulnerability", "Zero-day",
];

function label(name: string) {
  return name.replace(/_/g, " ");
}

export default function TrendGallery() {
  const [lightbox, setLightbox] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const filtered = THREATS.filter((t) =>
    label(t).toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-white">Historical Trend Gallery</h1>
        <p className="text-slate-400 text-sm mt-1">
          Full historical research trend for each cyber threat — actual academic
          publication counts from 2011 to 2022, used to train the forecast model
        </p>
      </div>

      <Hint text="These charts show the real historical data the model was trained on. Each plot shows monthly academic publication counts mentioning that threat from July 2011 to December 2022. Upward trends indicate growing research interest." />

      <input
        type="text"
        placeholder="Search threats…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="w-64 px-3 py-2 text-sm bg-[#1e293b] border border-[#334155] rounded-lg text-slate-300 placeholder-slate-600 outline-none"
      />

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
        {filtered.map((threat) => (
          <button
            key={threat}
            onClick={() => setLightbox(threat)}
            className="group bg-[#1e293b] border border-[#334155] rounded-xl overflow-hidden hover:border-blue-500/50 transition-all hover:shadow-lg hover:shadow-blue-500/5 text-left"
          >
            <img
              src={`/api/outputs/trend_plots/${threat}.png`}
              alt={label(threat)}
              className="w-full h-32 object-cover group-hover:opacity-90 transition-opacity"
              onError={(e) => {
                (e.target as HTMLImageElement).style.display = "none";
              }}
            />
            <div className="px-3 py-2">
              <div className="text-slate-200 text-xs font-medium truncate">
                {label(threat)}
              </div>
              <div className="text-slate-500 text-xs mt-0.5">
                2011 – 2022 history
              </div>
            </div>
          </button>
        ))}
      </div>

      {/* Lightbox */}
      {lightbox && (
        <div
          className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-6"
          onClick={() => setLightbox(null)}
        >
          <div
            className="bg-[#1e293b] border border-[#334155] rounded-2xl overflow-hidden max-w-3xl w-full"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-3 border-b border-[#334155]">
              <div>
                <span className="text-white font-semibold">{label(lightbox)}</span>
                <span className="text-slate-400 text-xs ml-2">
                  Historical research trend · 2011–2022
                </span>
              </div>
              <button
                onClick={() => setLightbox(null)}
                className="text-slate-400 hover:text-white"
              >
                <X size={18} />
              </button>
            </div>
            <img
              src={`/api/outputs/trend_plots/${lightbox}.png`}
              alt={label(lightbox)}
              className="w-full"
            />
            <div className="px-5 py-3 text-xs text-slate-400">
              Monthly academic publication count mentioning "{label(lightbox)}"
              — source: Elsevier Scopus API. This data was used to train the
              B-MTGNN forecast model.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
