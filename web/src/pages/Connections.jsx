import { useState, useEffect, useCallback } from 'react'
import { Activity, Search, RefreshCw, Filter, Tag, Calendar, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react'
import { useSession } from '../context/SessionContext'

const API = 'http://localhost:8000'

// ── Module-level cache for instant tab switches ──
const _connCache = new Map()

// Protocol → neon color map
const PROTO_COLORS = {
    'TLSv1.2': '#00f3ff', 'TLSv1.3': '#00f3ff', 'TLSv1': '#00b8cc',
    'TCP': '#bc13fe', 'UDP': '#ffaa00', 'QUIC': '#00ff73',
    'HTTP': '#ff9500', 'HTTP/JSON': '#ff9500', 'DNS': '#6ec6ff',
    'SSLv2': '#ff6b9d', 'SSL': '#ff6b9d', 'SSHv2': '#c5e1a5', 'SSH': '#c5e1a5',
    'ICMP': '#fff59d', 'ICMPv6': '#fff59d', 'ARP': '#ffcc80',
    'MDNS': '#80deea', 'NTP': '#b39ddb', 'DHCP': '#ef9a9a',
}
const protoColor = (p) => PROTO_COLORS[p] || '#8b8b9b'

// Tag → color/label config
const TAG_CONFIG = {
    beaconing: { color: '#ff2a2a', icon: '⏱', label: 'Beaconing' },
    data_exfil: { color: '#ff6b00', icon: '⚠', label: 'Data Exfil' },
    traffic_anomaly: { color: '#ffaa00', icon: '⚡', label: 'Anomaly' },
    new_dest: { color: '#00f3ff', icon: '🆕', label: 'New Dest' },
}

const DirectionBadge = ({ dir }) => {
    const isIn = dir === 'INCOMING'
    return (
        <span style={{
            fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px',
            background: isIn ? 'rgba(0,243,255,0.1)' : 'rgba(188,19,254,0.1)',
            color: isIn ? '#00f3ff' : '#bc13fe',
            border: `1px solid ${isIn ? 'rgba(0,243,255,0.25)' : 'rgba(188,19,254,0.25)'}`,
            letterSpacing: '0.05em',
        }}>
            {isIn ? '↓ IN' : '↑ OUT'}
        </span>
    )
}

const ProtoBadge = ({ proto }) => {
    const color = protoColor(proto)
    return (
        <span style={{
            fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px',
            color, background: `${color}15`,
            border: `1px solid ${color}35`,
            letterSpacing: '0.03em',
            fontFamily: 'monospace',
        }}>
            {proto}
        </span>
    )
}

const TagBadge = ({ tag }) => {
    const cfg = TAG_CONFIG[tag]
    if (!cfg) return <span style={{ color: '#3d3d4e', fontSize: '0.7rem' }}>—</span>
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: '4px',
            fontSize: '0.65rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px',
            color: cfg.color,
            background: `${cfg.color}12`,
            border: `1px solid ${cfg.color}30`,
            letterSpacing: '0.04em',
            whiteSpace: 'nowrap',
        }}>
            <span style={{ fontSize: '0.7rem' }}>{cfg.icon}</span>
            {cfg.label}
        </span>
    )
}

// Shared input style
const inputStyle = {
    padding: '0.5rem 0.75rem',
    background: 'rgba(255,255,255,0.04)',
    border: '1px solid rgba(255,255,255,0.08)',
    borderRadius: '8px',
    color: '#fff',
    fontSize: '0.82rem',
    outline: 'none',
    transition: 'border-color 0.2s',
}

const Connections = () => {
    const { sessionId } = useSession()
    const cacheKey = `connections-${sessionId || 0}`
    const cached = _connCache.get(cacheKey)

    const [connections, setConnections] = useState(cached?.connections || [])
    const [allProtocols, setAllProtocols] = useState(cached?.protocols || [])
    const [allTags, setAllTags] = useState(cached?.tags || [])
    const [totalCount, setTotalCount] = useState(cached?.totalCount || 0)
    const [totalPages, setTotalPages] = useState(cached?.totalPages || 1)
    const [loading, setLoading] = useState(!cached)

    // Filters
    const [search, setSearch] = useState('')
    const [proto, setProto] = useState('')
    const [port, setPort] = useState('')
    const [tag, setTag] = useState('')
    const [dateFrom, setDateFrom] = useState('')
    const [dateTo, setDateTo] = useState('')

    // Pagination
    const [page, setPage] = useState(1)
    const [perPage, setPerPage] = useState(50)

    const [expanded, setExpanded] = useState(null)
    const [aiAnalysis, setAiAnalysis] = useState({})
    const [aiLoading, setAiLoading] = useState({})

    const fetchConnections = useCallback(async () => {
        // Only show spinner on cold start (no cache)
        if (!_connCache.has(cacheKey)) setLoading(true)
        try {
            const params = new URLSearchParams({
                page, per_page: perPage,
                search, protocol: proto, tag,
                date_from: dateFrom, date_to: dateTo,
            })
            if (port) params.set('port', port)
            if (sessionId) params.set('session_id', sessionId)
            const res = await fetch(`${API}/api/connections?${params}`)
            const data = await res.json()
            setConnections(data.connections || [])
            setAllProtocols(data.protocols || [])
            setAllTags(data.tags || [])
            setTotalCount(data.total_count || 0)
            setTotalPages(data.total_pages || 1)
            // Cache default view for instant tab switches
            if (!search && !proto && !port && !tag && !dateFrom && !dateTo && page === 1) {
                _connCache.set(cacheKey, {
                    connections: data.connections || [],
                    protocols: data.protocols || [],
                    tags: data.tags || [],
                    totalCount: data.total_count || 0,
                    totalPages: data.total_pages || 1,
                })
            }
        } catch (e) {
            // silently fail
        } finally {
            setLoading(false)
        }
    }, [page, perPage, search, proto, port, tag, dateFrom, dateTo, sessionId, cacheKey])

    // Reset to page 1 when filters change
    useEffect(() => {
        setPage(1)
    }, [search, proto, port, tag, dateFrom, dateTo, perPage])

    useEffect(() => {
        fetchConnections()
    }, [fetchConnections])

    const toggleExpand = (id) => setExpanded(prev => prev === id ? null : id)

    const fmtTime = (isoStr) => {
        if (!isoStr) return '—'
        // Display date + time nicely
        const d = new Date(isoStr)
        const pad = n => String(n).padStart(2, '0')
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    }

    // Calculate result range text
    const rangeStart = (page - 1) * perPage + 1
    const rangeEnd = Math.min(page * perPage, totalCount)

    // Quick date presets
    const setPreset = (label) => {
        const now = new Date()
        const pad = n => String(n).padStart(2, '0')
        const fmt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
        const fmtFull = d => `${fmt(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}`

        if (label === 'today') {
            setDateFrom(fmt(now))
            setDateTo('')
        } else if (label === 'yesterday') {
            const y = new Date(now); y.setDate(y.getDate() - 1)
            setDateFrom(fmt(y))
            setDateTo(fmt(y))
        } else if (label === '7d') {
            const d = new Date(now); d.setDate(d.getDate() - 7)
            setDateFrom(fmt(d))
            setDateTo('')
        } else if (label === '30d') {
            const d = new Date(now); d.setDate(d.getDate() - 30)
            setDateFrom(fmt(d))
            setDateTo('')
        } else if (label === '1h') {
            const d = new Date(now.getTime() - 3600000)
            setDateFrom(fmtFull(d))
            setDateTo('')
        } else if (label === 'all') {
            setDateFrom('')
            setDateTo('')
        }
    }

    const presetBtnStyle = (active) => ({
        padding: '3px 10px', borderRadius: '6px', border: 'none',
        fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer',
        background: active ? 'rgba(0,243,255,0.15)' : 'rgba(255,255,255,0.04)',
        color: active ? '#00f3ff' : '#5a5a6e',
        transition: 'all 0.15s',
    })

    const pageBtnStyle = (disabled) => ({
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        width: '32px', height: '32px', borderRadius: '6px',
        border: '1px solid rgba(255,255,255,0.08)',
        background: 'rgba(255,255,255,0.04)',
        color: disabled ? '#2a2a3a' : '#8b8b9b',
        cursor: disabled ? 'default' : 'pointer',
        fontSize: '0.8rem',
        transition: 'all 0.15s',
        pointerEvents: disabled ? 'none' : 'auto',
    })

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">Connections</h1>
                    <p className="page-subtitle">
                        {totalCount.toLocaleString()} total
                        {(search || proto || port || tag || dateFrom || dateTo) && ' (filtered)'}
                    </p>
                </div>
                <button
                    onClick={fetchConnections}
                    style={{
                        display: 'flex', alignItems: 'center', gap: '0.4rem',
                        padding: '0.45rem 0.9rem', borderRadius: '8px',
                        background: 'rgba(0,243,255,0.1)', border: '1px solid rgba(0,243,255,0.2)',
                        color: '#00f3ff', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600,
                    }}
                >
                    <RefreshCw size={13} />
                    Refresh
                </button>
            </div>

            {/* ── Filters Row 1: Search + Protocol + Tag + Per Page ── */}
            <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '0.6rem', flexWrap: 'wrap' }}>
                <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
                    <Search size={15} style={{
                        position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                        color: '#5a5a6e', pointerEvents: 'none'
                    }} />
                    <input
                        type="text"
                        placeholder="Search IP address or protocol…"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        style={{ ...inputStyle, width: '100%', paddingLeft: '2.2rem', boxSizing: 'border-box' }}
                        onFocus={e => e.target.style.borderColor = 'rgba(0,243,255,0.4)'}
                        onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.08)'}
                    />
                </div>

                <div style={{ position: 'relative' }}>
                    <Filter size={14} style={{
                        position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                        color: '#5a5a6e', pointerEvents: 'none'
                    }} />
                    <select value={proto} onChange={e => setProto(e.target.value)}
                        style={{ ...inputStyle, paddingLeft: '2.2rem', color: proto ? '#00f3ff' : '#5a5a6e', cursor: 'pointer' }}>
                        <option value="">All protocols</option>
                        {allProtocols.map(p => <option key={p} value={p}>{p}</option>)}
                    </select>
                </div>

                <div style={{ position: 'relative' }}>
                    <Tag size={14} style={{
                        position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
                        color: '#5a5a6e', pointerEvents: 'none'
                    }} />
                    <select value={tag} onChange={e => setTag(e.target.value)}
                        style={{ ...inputStyle, paddingLeft: '2.2rem', color: tag ? (TAG_CONFIG[tag]?.color || '#ffaa00') : '#5a5a6e', cursor: 'pointer' }}>
                        <option value="">All tags</option>
                        {allTags.map(t => <option key={t} value={t}>{TAG_CONFIG[t]?.label || t}</option>)}
                    </select>
                </div>

                <input
                    type="number"
                    placeholder="Port…"
                    value={port}
                    onChange={e => setPort(e.target.value)}
                    min="0" max="65535"
                    style={{ ...inputStyle, width: '90px', textAlign: 'center' }}
                    onFocus={e => e.target.style.borderColor = 'rgba(0,243,255,0.4)'}
                    onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.08)'}
                />

                <select value={perPage} onChange={e => setPerPage(Number(e.target.value))}
                    style={{ ...inputStyle, color: '#8b8b9b', cursor: 'pointer' }}>
                    <option value={25}>25 / page</option>
                    <option value={50}>50 / page</option>
                    <option value={100}>100 / page</option>
                    <option value={200}>200 / page</option>
                </select>
            </div>

            {/* ── Filters Row 2: Date Range ── */}
            <div style={{
                display: 'flex', gap: '0.6rem', marginBottom: '1rem',
                alignItems: 'center', flexWrap: 'wrap',
            }}>
                <Calendar size={14} style={{ color: '#5a5a6e', flexShrink: 0 }} />

                {/* Quick presets */}
                <div style={{ display: 'flex', gap: '0.35rem' }}>
                    {[
                        ['1h', 'Last hour'],
                        ['today', 'Today'],
                        ['yesterday', 'Yesterday'],
                        ['7d', '7 days'],
                        ['30d', '30 days'],
                        ['all', 'All time'],
                    ].map(([key, label]) => (
                        <button key={key} onClick={() => setPreset(key)}
                            style={presetBtnStyle(!dateFrom && !dateTo && key === 'all')}>
                            {label}
                        </button>
                    ))}
                </div>

                <div style={{ width: '1px', height: '20px', background: 'rgba(255,255,255,0.08)', margin: '0 0.25rem' }} />

                {/* Custom date inputs */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <span style={{ fontSize: '0.72rem', color: '#5a5a6e' }}>From</span>
                    <input
                        type="datetime-local"
                        value={dateFrom}
                        onChange={e => setDateFrom(e.target.value)}
                        style={{ ...inputStyle, fontSize: '0.78rem', padding: '4px 8px', colorScheme: 'dark' }}
                    />
                    <span style={{ fontSize: '0.72rem', color: '#5a5a6e' }}>To</span>
                    <input
                        type="datetime-local"
                        value={dateTo}
                        onChange={e => setDateTo(e.target.value)}
                        style={{ ...inputStyle, fontSize: '0.78rem', padding: '4px 8px', colorScheme: 'dark' }}
                    />
                    {(dateFrom || dateTo) && (
                        <button onClick={() => { setDateFrom(''); setDateTo('') }}
                            style={{
                                fontSize: '0.7rem', color: '#5a5a6e', background: 'none',
                                border: 'none', cursor: 'pointer', padding: '2px 6px',
                            }}>
                            ✕ Clear
                        </button>
                    )}
                </div>
            </div>

            {/* ── Table ── */}
            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                {loading ? (
                    <div style={{ padding: '3rem', textAlign: 'center', color: '#5a5a6e' }}>
                        <Activity size={32} style={{ marginBottom: '0.75rem', opacity: 0.3 }} />
                        <p>Loading connections…</p>
                    </div>
                ) : connections.length === 0 ? (
                    <div style={{ padding: '3rem', textAlign: 'center', color: '#5a5a6e' }}>
                        <Activity size={32} style={{ marginBottom: '0.75rem', opacity: 0.3 }} />
                        <p>No connections found{(search || proto || tag || dateFrom || dateTo) ? ' for these filters' : ''}</p>
                    </div>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                            <thead>
                                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                                    {['Source', 'Destination', 'Protocol', 'Direction', 'Packets', 'Bytes', 'Tags', 'Time'].map(h => (
                                        <th key={h} style={{
                                            padding: '0.75rem 1rem', textAlign: 'left',
                                            color: '#5a5a6e', fontWeight: 600, fontSize: '0.7rem',
                                            letterSpacing: '0.08em', textTransform: 'uppercase',
                                            whiteSpace: 'nowrap',
                                        }}>
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {connections.map((c, i) => (
                                    <>
                                        <tr
                                            key={c.id}
                                            onClick={() => toggleExpand(c.id)}
                                            style={{
                                                borderBottom: '1px solid rgba(255,255,255,0.04)',
                                                cursor: 'pointer',
                                                background: expanded === c.id
                                                    ? 'rgba(0,243,255,0.05)'
                                                    : c.tags
                                                        ? `${TAG_CONFIG[c.tags]?.color || '#ffaa00'}08`
                                                        : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                                                transition: 'background 0.15s',
                                            }}
                                            onMouseEnter={e => { if (expanded !== c.id) e.currentTarget.style.background = 'rgba(255,255,255,0.04)' }}
                                            onMouseLeave={e => {
                                                if (expanded !== c.id)
                                                    e.currentTarget.style.background = c.tags
                                                        ? `${TAG_CONFIG[c.tags]?.color || '#ffaa00'}08`
                                                        : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)'
                                            }}
                                        >
                                            <td style={{ padding: '0.6rem 1rem', fontFamily: 'monospace', color: '#e0e0e0' }}>{c.src}</td>
                                            <td style={{ padding: '0.6rem 1rem', fontFamily: 'monospace', color: '#e0e0e0' }}>{c.dst}</td>
                                            <td style={{ padding: '0.6rem 1rem' }}><ProtoBadge proto={c.protocol} /></td>
                                            <td style={{ padding: '0.6rem 1rem' }}><DirectionBadge dir={c.direction} /></td>
                                            <td style={{ padding: '0.6rem 1rem', color: '#8b8b9b', fontFamily: 'monospace' }}>{c.packets.toLocaleString()}</td>
                                            <td style={{ padding: '0.6rem 1rem', color: '#8b8b9b', fontFamily: 'monospace' }}>{c.bytes}</td>
                                            <td style={{ padding: '0.6rem 1rem' }}><TagBadge tag={c.tags} /></td>
                                            <td style={{ padding: '0.6rem 1rem', color: '#5a5a6e', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>{fmtTime(c.time)}</td>
                                        </tr>
                                        {expanded === c.id && (
                                            <tr key={`${c.id}-detail`} style={{ background: 'rgba(0,243,255,0.03)' }}>
                                                <td colSpan={8} style={{ padding: '0.75rem 1rem 1rem 2rem' }}>
                                                    <div style={{ display: 'flex', gap: '2.5rem', flexWrap: 'wrap' }}>
                                                        {[
                                                            ['Connection ID', `#${c.id}`],
                                                            ['Source IP', c.src_ip],
                                                            ['Destination IP', c.dst_ip],
                                                            ['Protocol', c.protocol],
                                                            ['Direction', c.direction],
                                                            ['Packets', c.packets.toLocaleString()],
                                                            ['Data', c.bytes],
                                                            ['Started', fmtTime(c.time)],
                                                        ].map(([label, val]) => (
                                                            <div key={label} style={{ minWidth: '120px' }}>
                                                                <div style={{ fontSize: '0.65rem', color: '#3d3d4e', marginBottom: '2px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
                                                                <div style={{ fontSize: '0.8rem', color: '#c0c0c0', fontFamily: typeof val === 'string' && val.includes('.') ? 'monospace' : 'inherit' }}>{val}</div>
                                                            </div>
                                                        ))}
                                                    </div>

                                                    {/* ── AI Analyze Button ── */}
                                                    <div style={{ marginTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '0.85rem' }}>
                                                        {!aiAnalysis[c.id] && !aiLoading[c.id] && (
                                                            <button
                                                                onClick={(e) => {
                                                                    e.stopPropagation()
                                                                    setAiLoading(prev => ({ ...prev, [c.id]: true }))
                                                                    fetch(`${API}/api/connections/analyze`, {
                                                                        method: 'POST',
                                                                        headers: { 'Content-Type': 'application/json' },
                                                                        body: JSON.stringify({
                                                                            conn_id: c.id,
                                                                            src_ip: c.src_ip,
                                                                            dst_ip: c.dst_ip,
                                                                            src_port: c.src_port || 0,
                                                                            dst_port: c.dst_port || 0,
                                                                            protocol: c.protocol,
                                                                            direction: c.direction,
                                                                            packets: c.packets,
                                                                            bytes_str: c.bytes,
                                                                            tags: c.tags,
                                                                            time: c.time,
                                                                        }),
                                                                    })
                                                                        .then(r => r.json())
                                                                        .then(data => {
                                                                            setAiAnalysis(prev => ({ ...prev, [c.id]: data.explanation || 'No analysis available.' }))
                                                                            setAiLoading(prev => ({ ...prev, [c.id]: false }))
                                                                        })
                                                                        .catch(() => {
                                                                            setAiAnalysis(prev => ({ ...prev, [c.id]: 'Failed to get AI analysis. Please try again.' }))
                                                                            setAiLoading(prev => ({ ...prev, [c.id]: false }))
                                                                        })
                                                                }}
                                                                style={{
                                                                    padding: '0.55rem 1.2rem',
                                                                    background: 'linear-gradient(135deg, rgba(0,243,255,0.12), rgba(138,43,226,0.08))',
                                                                    border: '1px solid rgba(0,243,255,0.25)',
                                                                    borderRadius: '8px',
                                                                    color: '#7dd8e8',
                                                                    fontSize: '0.78rem',
                                                                    fontWeight: 600,
                                                                    cursor: 'pointer',
                                                                    transition: 'all 0.2s',
                                                                    display: 'flex',
                                                                    alignItems: 'center',
                                                                    gap: '0.5rem',
                                                                }}
                                                                onMouseEnter={e => {
                                                                    e.currentTarget.style.background = 'linear-gradient(135deg, rgba(0,243,255,0.2), rgba(138,43,226,0.14))'
                                                                    e.currentTarget.style.borderColor = 'rgba(0,243,255,0.4)'
                                                                }}
                                                                onMouseLeave={e => {
                                                                    e.currentTarget.style.background = 'linear-gradient(135deg, rgba(0,243,255,0.12), rgba(138,43,226,0.08))'
                                                                    e.currentTarget.style.borderColor = 'rgba(0,243,255,0.25)'
                                                                }}
                                                            >
                                                                🤖 Analyze Connection
                                                            </button>
                                                        )}

                                                        {aiLoading[c.id] && (
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: '#7dd8e8', fontSize: '0.8rem' }}>
                                                                <div style={{
                                                                    width: '16px', height: '16px',
                                                                    border: '2px solid rgba(0,243,255,0.3)',
                                                                    borderTopColor: '#7dd8e8',
                                                                    borderRadius: '50%',
                                                                    animation: 'spin 0.8s linear infinite',
                                                                }} />
                                                                Analyzing connection with AI...
                                                            </div>
                                                        )}

                                                        {aiAnalysis[c.id] && !aiLoading[c.id] && (
                                                            <div style={{
                                                                marginTop: '0.5rem',
                                                                padding: '1rem 1.25rem',
                                                                background: 'linear-gradient(135deg, rgba(0,243,255,0.06), rgba(138,43,226,0.04))',
                                                                border: '1px solid rgba(0,243,255,0.15)',
                                                                borderRadius: '10px',
                                                                animation: 'fadeIn 0.3s ease',
                                                            }}>
                                                                <div style={{
                                                                    fontSize: '0.68rem', color: '#5a9aaa', fontWeight: 700,
                                                                    textTransform: 'uppercase', letterSpacing: '0.08em',
                                                                    marginBottom: '0.6rem',
                                                                    display: 'flex', alignItems: 'center', gap: '0.4rem',
                                                                }}>
                                                                    🤖 AI Connection Analysis
                                                                </div>
                                                                <div style={{
                                                                    fontSize: '0.82rem', color: '#d0d0e0',
                                                                    lineHeight: '1.6', whiteSpace: 'pre-wrap',
                                                                }}>
                                                                    {aiAnalysis[c.id].split('**').map((part, idx) =>
                                                                        idx % 2 === 1
                                                                            ? <strong key={idx} style={{ color: '#a0e8ff' }}>{part}</strong>
                                                                            : <span key={idx}>{part}</span>
                                                                    )}
                                                                </div>
                                                                <div style={{
                                                                    marginTop: '0.75rem', paddingTop: '0.5rem',
                                                                    borderTop: '1px solid rgba(0,243,255,0.1)',
                                                                    fontSize: '0.62rem', color: '#3d5a6e',
                                                                    display: 'flex', justifyContent: 'space-between',
                                                                }}>
                                                                    <span>Powered by Groq AI</span>
                                                                    <button
                                                                        onClick={(e) => {
                                                                            e.stopPropagation()
                                                                            setAiAnalysis(prev => { const next = { ...prev }; delete next[c.id]; return next })
                                                                            setAiLoading(prev => ({ ...prev, [c.id]: true }))
                                                                            fetch(`${API}/api/connections/analyze`, {
                                                                                method: 'POST',
                                                                                headers: { 'Content-Type': 'application/json' },
                                                                                body: JSON.stringify({
                                                                                    conn_id: c.id, src_ip: c.src_ip, dst_ip: c.dst_ip,
                                                                                    src_port: c.src_port || 0, dst_port: c.dst_port || 0,
                                                                                    protocol: c.protocol, direction: c.direction,
                                                                                    packets: c.packets, bytes_str: c.bytes,
                                                                                    tags: c.tags, time: c.time,
                                                                                }),
                                                                            })
                                                                                .then(r => r.json())
                                                                                .then(data => {
                                                                                    setAiAnalysis(prev => ({ ...prev, [c.id]: data.explanation || 'No analysis available.' }))
                                                                                    setAiLoading(prev => ({ ...prev, [c.id]: false }))
                                                                                })
                                                                                .catch(() => {
                                                                                    setAiAnalysis(prev => ({ ...prev, [c.id]: 'Failed to get analysis.' }))
                                                                                    setAiLoading(prev => ({ ...prev, [c.id]: false }))
                                                                                })
                                                                        }}
                                                                        style={{ background: 'none', border: 'none', color: '#3d5a6e', cursor: 'pointer', fontSize: '0.62rem', textDecoration: 'underline' }}
                                                                    >Re-analyze</button>
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* ── Pagination Bar ── */}
                {totalCount > 0 && (
                    <div style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        padding: '0.75rem 1rem',
                        borderTop: '1px solid rgba(255,255,255,0.06)',
                        fontSize: '0.78rem', color: '#5a5a6e',
                    }}>
                        <span>
                            Showing <span style={{ color: '#e0e0e0' }}>{rangeStart.toLocaleString()}–{rangeEnd.toLocaleString()}</span> of{' '}
                            <span style={{ color: '#e0e0e0' }}>{totalCount.toLocaleString()}</span> connections
                        </span>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <button onClick={() => setPage(1)} style={pageBtnStyle(page === 1)}>
                                <ChevronsLeft size={14} />
                            </button>
                            <button onClick={() => setPage(p => Math.max(1, p - 1))} style={pageBtnStyle(page === 1)}>
                                <ChevronLeft size={14} />
                            </button>

                            {/* Page number buttons */}
                            {(() => {
                                const pages = []
                                let start = Math.max(1, page - 2)
                                let end = Math.min(totalPages, start + 4)
                                if (end - start < 4) start = Math.max(1, end - 4)
                                for (let i = start; i <= end; i++) pages.push(i)
                                return pages.map(p => (
                                    <button key={p} onClick={() => setPage(p)}
                                        style={{
                                            ...pageBtnStyle(false),
                                            background: p === page ? 'rgba(0,243,255,0.2)' : 'rgba(255,255,255,0.04)',
                                            color: p === page ? '#00f3ff' : '#5a5a6e',
                                            border: p === page ? '1px solid rgba(0,243,255,0.3)' : '1px solid rgba(255,255,255,0.08)',
                                            fontWeight: p === page ? 700 : 400,
                                            fontSize: '0.75rem',
                                        }}>
                                        {p}
                                    </button>
                                ))
                            })()}

                            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} style={pageBtnStyle(page === totalPages)}>
                                <ChevronRight size={14} />
                            </button>
                            <button onClick={() => setPage(totalPages)} style={pageBtnStyle(page === totalPages)}>
                                <ChevronsRight size={14} />
                            </button>

                            <span style={{ marginLeft: '0.5rem', fontSize: '0.72rem' }}>
                                Page {page} of {totalPages.toLocaleString()}
                            </span>
                        </div>
                    </div>
                )}
            </div>
        </>
    )
}

export default Connections
