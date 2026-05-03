import { Info } from "lucide-react";

export default function Hint({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 bg-slate-800/60 border border-slate-700/50 rounded-lg px-3 py-2 text-xs text-slate-400 leading-relaxed">
      <Info size={13} className="mt-0.5 shrink-0 text-blue-400" />
      {text}
    </div>
  );
}
