import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { api, GraphData } from "../api/client";
import Hint from "../components/Hint";

interface NodeObj {
  id: string;
  type: string;
  x?: number;
  y?: number;
}

export default function ThreatGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ w: 800, h: 600 });
  const [selected, setSelected] = useState<NodeObj | null>(null);

  const { data: graphData, isLoading } = useQuery<GraphData>({
    queryKey: ["graph"],
    queryFn: () => api.get("/graph/").then((r) => r.data),
  });

  useEffect(() => {
    if (!containerRef.current) return;
    const obs = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setDimensions({ w: width, h: height });
    });
    obs.observe(containerRef.current);
    return () => obs.disconnect();
  }, []);

  const handleNodeClick = useCallback((node: object) => {
    setSelected((prev) => {
      const n = node as NodeObj;
      return prev?.id === n.id ? null : n;
    });
  }, []);

  const nodeColor = (node: object) =>
    (node as NodeObj).type === "threat" ? "#ef4444" : "#3b82f6";

  const nodeLabel = (node: object) => {
    const n = node as NodeObj;
    return `${n.id} (${n.type === "threat" ? "Cyber Threat" : "Defense Tech"})`;
  };

  const threatCount = graphData?.nodes.filter((n) => n.type === "threat").length ?? 0;
  const patCount = graphData?.nodes.filter((n) => n.type === "pat").length ?? 0;

  return (
    <div className="space-y-4 h-[calc(100vh-3rem)] flex flex-col">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Threat–Defense Relationship Graph
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Network map showing which defense technologies are linked to which
            cyber threats based on co-occurrence patterns in academic literature
          </p>
        </div>
        {/* Legend */}
        <div className="shrink-0 bg-[#1e293b] border border-[#334155] rounded-xl px-4 py-3 text-xs space-y-2">
          <div className="text-slate-400 font-medium mb-1">Legend</div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-red-500 inline-block" />
            <span className="text-slate-300">
              Cyber Threat ({threatCount} nodes)
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-blue-500 inline-block" />
            <span className="text-slate-300">
              Defense Technology ({patCount} nodes)
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-5 h-px bg-slate-500 inline-block" />
            <span className="text-slate-400">
              Research co-occurrence link ({graphData?.links.length ?? 0})
            </span>
          </div>
        </div>
      </div>

      <Hint text="Each line (edge) connects a threat to a defense technology that addresses it in research. Nodes closer together share more connections. Click any node to see its name and type. Scroll to zoom, drag nodes to rearrange." />

      {selected && (
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl px-4 py-3 text-sm flex items-center gap-3">
          <span
            className={`w-2.5 h-2.5 rounded-full ${
              selected.type === "threat" ? "bg-red-500" : "bg-blue-500"
            }`}
          />
          <span className="text-white font-medium">{selected.id}</span>
          <span
            className={`text-xs px-2 py-0.5 rounded-full ${
              selected.type === "threat"
                ? "bg-red-500/20 text-red-400"
                : "bg-blue-500/20 text-blue-400"
            }`}
          >
            {selected.type === "threat" ? "Cyber Threat" : "Defense Technology"}
          </span>
          <button
            onClick={() => setSelected(null)}
            className="ml-auto text-slate-500 hover:text-slate-300 text-xs"
          >
            Dismiss
          </button>
        </div>
      )}

      <div
        ref={containerRef}
        className="flex-1 bg-[#1e293b] border border-[#334155] rounded-xl overflow-hidden"
      >
        {isLoading ? (
          <div className="h-full flex items-center justify-center text-slate-500">
            Loading graph…
          </div>
        ) : graphData ? (
          <ForceGraph2D
            graphData={graphData}
            width={dimensions.w}
            height={dimensions.h}
            backgroundColor="#1e293b"
            nodeColor={nodeColor}
            nodeLabel={nodeLabel}
            nodeRelSize={5}
            linkColor={() => "#475569"}
            linkWidth={0.8}
            onNodeClick={handleNodeClick}
            nodeCanvasObjectMode={() => "after"}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const n = node as NodeObj;
              if (globalScale < 1.5) return;
              const label = n.id;
              const fontSize = Math.max(8, 11 / globalScale);
              ctx.font = `${fontSize}px Sans-Serif`;
              ctx.fillStyle =
                n.type === "threat"
                  ? "rgba(252,165,165,0.9)"
                  : "rgba(147,197,253,0.9)";
              ctx.fillText(label, (n.x ?? 0) + 6, (n.y ?? 0) + fontSize / 2);
            }}
          />
        ) : null}
      </div>
    </div>
  );
}
