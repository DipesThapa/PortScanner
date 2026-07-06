import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import PropTypes from "prop-types";

const NetworkGraph = ({ scan }) => {
    const containerRef = useRef(null);
    const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

    useEffect(() => {
        if (!containerRef.current) return;
        const resizeObserver = new ResizeObserver((entries) => {
            for (let entry of entries) {
                setDimensions({
                    width: entry.contentRect.width,
                    height: entry.contentRect.height,
                });
            }
        });
        resizeObserver.observe(containerRef.current);
        return () => resizeObserver.disconnect();
    }, []);

    const graphData = useMemo(() => {
        if (!scan) return { nodes: [], links: [] };

        const nodes = [];
        const links = [];
        const seenNodes = new Set();

        // 1. Central Node: The Target
        const targetId = scan.job_id ? `scan-${scan.job_id}` : "root";
        nodes.push({
            id: targetId,
            name: "TARGET",
            val: 20,
            color: "#3b82f6", // Primary Blue
            type: "root",
        });
        seenNodes.add(targetId);

        // 2. Service Intel Findings (Ports/Services)
        const findings = scan.plugins?.["service-intel"]?.findings || [];
        findings.forEach((finding, idx) => {
            const portId = `port-${finding.port || idx}`;

            // Determine risk color
            let color = "#10b981"; // Green (Safe)
            const risk = (finding.risk || "").toLowerCase();
            if (risk === "critical" || risk === "high") color = "#ef4444"; // Red
            else if (risk === "medium") color = "#f59e0b"; // Orange

            if (!seenNodes.has(portId)) {
                nodes.push({
                    id: portId,
                    name: `${finding.port}/${finding.protocol}`,
                    val: 10,
                    color: color,
                    type: "port",
                    desc: finding.summary || finding.service,
                });
                seenNodes.add(portId);

                links.push({
                    source: targetId,
                    target: portId,
                    color: "rgba(148, 163, 184, 0.2)",
                });
            }
        });

        // 3. Vulnerabilities (attached to ports if possible, or target)
        // For simplicity in V1, we color the ports based on risk (done above)
        // but we could add separate "Vuln" nodes if we wanted more density.

        return { nodes, links };
    }, [scan]);

    return (
        <div
            ref={containerRef}
            style={{
                width: "100%",
                height: "500px",
                background: "#0f172a",
                borderRadius: "8px",
                overflow: "hidden",
                border: "1px solid var(--border-subtle)"
            }}
        >
            <ForceGraph2D
                width={dimensions.width}
                height={dimensions.height}
                graphData={graphData}
                nodeLabel="name"
                nodeRelSize={6}
                linkColor={() => "rgba(148, 163, 184, 0.2)"}
                backgroundColor="#0f172a"
                onNodeClick={node => {
                    // Center view on node (react-force-graph has .centerAt() but simpler just to highlight for now)
                    // Future: could open a detailed modal
                }}
                nodeCanvasObject={(node, ctx, globalScale) => {
                    const label = node.name;
                    const fontSize = 12 / globalScale;
                    ctx.font = `${fontSize}px Sans-Serif`;
                    const textWidth = ctx.measureText(label).width;
                    const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2); // some padding

                    ctx.fillStyle = 'rgba(15, 23, 42, 0.8)';
                    ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);

                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = node.color;
                    ctx.fillText(label, node.x, node.y);

                    // Draw ring for outer selection
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, node.val ? node.val * 0.5 : 4, 0, 2 * Math.PI, false);
                    ctx.strokeStyle = node.color;
                    ctx.stroke();
                }}
            />
        </div>
    );
};

NetworkGraph.propTypes = {
    scan: PropTypes.object,
};

export default NetworkGraph;
