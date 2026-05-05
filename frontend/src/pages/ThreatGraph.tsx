import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { api, GraphData } from "../api/client";
import Hint from "../components/Hint";
import { getNodeInfo } from "../data/nodeInfo";

interface NodeObj {
  id: string;
  type: string;
  x?: number;
  y?: number;
}

function NodeInfoPanel({
  node,
  graphData,
  onClose,
}: {
  node: NodeObj;
  graphData: GraphData;
  onClose: () => void;
}) {
  const info = getNodeInfo(node.id, node.type);
  const isThreat = node.type === "threat";

  // Build neighbor lists from links
  const neighbors = graphData.links.reduce<{ id: string; type: string }[]>(
    (acc, link) => {
      const src = typeof link.source === "object" ? (link.source as NodeObj).id : link.source;
      const tgt = typeof link.target === "object" ? (link.target as NodeObj).id : link.target;
      if (src === node.id) {
        const n = graphData.nodes.find((x) => x.id === tgt);
        if (n) acc.push(n);
      } else if (tgt === node.id) {
        const n = graphData.nodes.find((x) => x.id === src);
        if (n) acc.push(n);
      }
      return acc;
    },
    []
  );

  const threats = neighbors.filter((n) => n.type === "threat");
  const pats = neighbors.filter((n) => n.type === "pat");

  return (
    <div className="w-72 shrink-0 bg-[#1e293b] border border-[#334155] rounded-xl flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-[#334155] flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className={`w-2.5 h-2.5 rounded-full shrink-0 ${
                isThreat ? "bg-red-500" : "bg-blue-500"
              }`}
            />
            <span className="text-white font-bold text-sm">{node.id}</span>
          </div>
          <span
            className={`mt-1 inline-block text-xs px-2 py-0.5 rounded-full ${
              isThreat
                ? "bg-red-500/20 text-red-400"
                : "bg-blue-500/20 text-blue-400"
            }`}
          >
            {isThreat ? "Cyber Threat" : "Defense Technology"}
          </span>
        </div>
        <button
          onClick={onClose}
          className="text-slate-500 hover:text-slate-300 text-lg leading-none shrink-0"
        >
          ×
        </button>
      </div>

      {/* Full name + description */}
      <div className="px-4 py-3 border-b border-[#334155] space-y-1">
        <p className="text-slate-300 text-xs font-semibold uppercase tracking-wider">
          Full Name
        </p>
        <p className="text-white text-sm font-medium">{info.fullName}</p>
        {info.description && (
          <p className="text-slate-400 text-xs leading-relaxed mt-1">
            {info.description}
          </p>
        )}
      </div>

      {/* Connected nodes */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">
          Connected ({neighbors.length} node{neighbors.length !== 1 ? "s" : ""})
        </p>

        {isThreat && pats.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-blue-400 text-xs font-medium">
              Defense Technologies ({pats.length})
            </p>
            {pats.map((n) => {
              const ni = getNodeInfo(n.id, n.type);
              return (
                <div
                  key={n.id}
                  className="bg-[#0f172a] rounded-lg px-3 py-2 space-y-0.5"
                >
                  <div className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-500 shrink-0" />
                    <span className="text-blue-300 text-xs font-semibold">
                      {n.id}
                    </span>
                  </div>
                  <p className="text-slate-400 text-xs pl-3">{ni.fullName}</p>
                </div>
              );
            })}
          </div>
        )}

        {!isThreat && threats.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-red-400 text-xs font-medium">
              Threats Addressed ({threats.length})
            </p>
            {threats.map((n) => {
              const ni = getNodeInfo(n.id, n.type);
              return (
                <div
                  key={n.id}
                  className="bg-[#0f172a] rounded-lg px-3 py-2 space-y-0.5"
                >
                  <div className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                    <span className="text-red-300 text-xs font-semibold">
                      {n.id}
                    </span>
                  </div>
                  <p className="text-slate-400 text-xs pl-3">{ni.fullName}</p>
                </div>
              );
            })}
          </div>
        )}

        {/* If a threat also connects to other threats (rare), or a PAT to other PATs */}
        {isThreat && threats.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-red-400 text-xs font-medium">
              Co-occurring Threats ({threats.length})
            </p>
            {threats.map((n) => {
              const ni = getNodeInfo(n.id, n.type);
              return (
                <div
                  key={n.id}
                  className="bg-[#0f172a] rounded-lg px-3 py-2 space-y-0.5"
                >
                  <div className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                    <span className="text-red-300 text-xs font-semibold">{n.id}</span>
                  </div>
                  <p className="text-slate-400 text-xs pl-3">{ni.fullName}</p>
                </div>
              );
            })}
          </div>
        )}

        {neighbors.length === 0 && (
          <p className="text-slate-500 text-xs">No connections found.</p>
        )}
      </div>
    </div>
  );
}

export default function ThreatGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ w: 0, h: 0 });
  const [selected, setSelected] = useState<NodeObj | null>(null);

  const { data: graphData, isLoading } = useQuery<GraphData>({
    queryKey: ["graph"],
    queryFn: () => api.get("/graph/").then((r) => r.data),
  });

  // Measure synchronously before first paint so the canvas never renders at 0×0
  useLayoutEffect(() => {
    if (!containerRef.current) return;
    const { width, height } = containerRef.current.getBoundingClientRect();
    if (width > 0 && height > 0) setDimensions({ w: width, h: height });
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;
    const obs = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      if (width > 0 && height > 0) setDimensions({ w: width, h: height });
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
    const info = getNodeInfo(n.id, n.type);
    return `${info.fullName} — ${n.type === "threat" ? "Cyber Threat" : "Defense Tech"}`;
  };

  const threatCount = graphData?.nodes.filter((n) => n.type === "threat").length ?? 0;
  const patCount = graphData?.nodes.filter((n) => n.type === "pat").length ?? 0;

  return (
    <div className="space-y-3 h-[calc(100vh-3rem)] flex flex-col">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Threat–Defense Relationship Graph
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Network map showing which defense technologies are linked to which
            cyber threats. Click any node to see its full name, description, and connections.
          </p>
        </div>
        {/* Legend */}
        <div className="shrink-0 bg-[#1e293b] border border-[#334155] rounded-xl px-4 py-3 text-xs space-y-2">
          <div className="text-slate-400 font-medium mb-1">Legend</div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-red-500 inline-block" />
            <span className="text-slate-300">Cyber Threat ({threatCount})</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-blue-500 inline-block" />
            <span className="text-slate-300">Defense Technology ({patCount})</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-5 h-px bg-slate-500 inline-block" />
            <span className="text-slate-400">
              Link ({graphData?.links.length ?? 0})
            </span>
          </div>
        </div>
      </div>

      <Hint text="Each line connects a threat to a defense technology linked in academic research. Click any node to open its info panel — full name, description, and all connected nodes. Scroll to zoom, drag to rearrange." />

      {/* Main area: graph + side panel */}
      <div className="flex-1 flex gap-3 min-h-0">
        <div
          ref={containerRef}
          className="flex-1 bg-[#1e293b] border border-[#334155] rounded-xl overflow-hidden"
        >
          {isLoading || dimensions.w === 0 ? (
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

        {selected && graphData && (
          <NodeInfoPanel
            node={selected}
            graphData={graphData}
            onClose={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  );
}
