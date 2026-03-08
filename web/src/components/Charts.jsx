import { useState, useRef, useCallback } from 'react'

export const Sparkline = ({ data, color }) => {
    const w = 200, h = 60
    const max = Math.max(...data)
    const min = Math.min(...data)
    const range = max - min || 1
    const points = data.map((v, i) =>
        `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * h}`
    ).join(' ')
    const fillPoints = `0,${h} ${points} ${w},${h}`

    return (
        <div className="sparkline-wrap">
            <svg width="100%" height="100%" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
                <defs>
                    <linearGradient id={`grad-${color}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={color} stopOpacity="0.4" />
                        <stop offset="100%" stopColor={color} stopOpacity="0" />
                    </linearGradient>
                </defs>
                <polygon points={fillPoints} fill={`url(#grad-${color})`} />
                <polyline points={points} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke" />
            </svg>
        </div>
    )
}

export const PieChart = ({ protocols, centerLabel, centerSub }) => {
    const [hovered, setHovered] = useState(null)
    const [tooltip, setTooltip] = useState(null)
    const svgRef = useRef(null)

    const cx = 50, cy = 50, r = 44
    const toRad = (deg) => (deg * Math.PI) / 180

    let cumAngle = -90
    const slices = protocols.map((p, i) => {
        const angle = (p.pct / 100) * 360
        const start = cumAngle
        cumAngle += angle
        const mid = start + angle / 2
        return { ...p, startAngle: start, endAngle: cumAngle, midAngle: mid, index: i }
    })

    const fmtPackets = (n) => {
        if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
        if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
        return String(n || 0)
    }

    const handleMouseMove = useCallback((e, slice) => {
        if (!svgRef.current) return
        const rect = svgRef.current.getBoundingClientRect()
        setTooltip({
            x: e.clientX - rect.left,
            y: e.clientY - rect.top,
            data: slice,
        })
        setHovered(slice.index)
    }, [])

    const handleMouseLeave = useCallback(() => {
        setTooltip(null)
        setHovered(null)
    }, [])

    const showHovered = hovered !== null && slices[hovered]
    const cLabel = showHovered ? `${slices[hovered].pct}%` : centerLabel
    const cSub = showHovered ? slices[hovered].name : centerSub

    return (
        <div className="pie-chart-container">
            <svg
                ref={svgRef}
                className="pie-chart-wrap"
                width="240"
                height="240"
                viewBox="0 0 100 100"
            >
                {slices.map((s) => {
                    const isHovered = hovered === s.index
                    const a1 = toRad(s.startAngle)
                    const a2 = toRad(s.endAngle)
                    const x1 = cx + r * Math.cos(a1)
                    const y1 = cy + r * Math.sin(a1)
                    const x2 = cx + r * Math.cos(a2)
                    const y2 = cy + r * Math.sin(a2)
                    const large = s.endAngle - s.startAngle > 180 ? 1 : 0
                    const d = `M${cx},${cy} L${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2} Z`

                    // Push hovered slice outward slightly
                    const midRad = toRad(s.midAngle)
                    const pushDist = isHovered ? 3 : 0
                    const tx = Math.cos(midRad) * pushDist
                    const ty = Math.sin(midRad) * pushDist

                    return (
                        <path
                            key={s.index}
                            d={d}
                            fill={s.color}
                            className="pie-slice"
                            style={{
                                filter: isHovered
                                    ? `drop-shadow(0 0 8px ${s.color}90)`
                                    : `drop-shadow(0 0 2px ${s.color}30)`,
                                transform: `translate(${tx}px, ${ty}px)`,
                                opacity: hovered !== null && !isHovered ? 0.5 : 1,
                            }}
                            onMouseMove={(e) => handleMouseMove(e, s)}
                            onMouseLeave={handleMouseLeave}
                        />
                    )
                })}
                <circle cx={cx} cy={cy} r="24" fill="#0a0a10" className="pie-center" />
                <text x={cx} y={cy - 2} textAnchor="middle" className="pie-center-text">
                    {cLabel}
                </text>
                <text x={cx} y={cy + 8} textAnchor="middle" className="pie-center-sub">
                    {cSub}
                </text>
            </svg>

            {/* Floating tooltip */}
            {tooltip && (
                <div
                    className="pie-tooltip"
                    style={{
                        left: tooltip.x,
                        top: tooltip.y - 10,
                    }}
                >
                    <div className="pie-tooltip-header">
                        <span className="pie-tooltip-dot" style={{ background: tooltip.data.color }} />
                        <span className="pie-tooltip-name">{tooltip.data.name}</span>
                    </div>
                    <div className="pie-tooltip-row">
                        <span>Packets</span>
                        <span className="pie-tooltip-val">{fmtPackets(tooltip.data.packets)}</span>
                    </div>
                    <div className="pie-tooltip-row">
                        <span>Share</span>
                        <span className="pie-tooltip-val">{tooltip.data.pct}%</span>
                    </div>
                </div>
            )}
        </div>
    )
}
