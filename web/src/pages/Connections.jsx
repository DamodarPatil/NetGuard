import { useState, useEffect, useCallback, useMemo } from 'react'
import { Activity, RefreshCw, Tag, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, ArrowUp, ArrowDown, ArrowUpDown, Unplug, Sparkles, X, Timer, ShieldAlert, Zap, MapPin } from 'lucide-react'
import { useSession } from '../context/SessionContext'
import { SkeletonTable, EmptyState } from '../components/Skeleton'
import FilterBar from '../components/FilterBar'

const API = 'http://localhost:8000'

// ── Module-level cache for instant tab switches ──
const _connCache = new Map()

// Protocol color map
const PROTO_COLORS = {
    'TLSv1.2': '#3b82f6', 'TLSv1.3': '#3b82f6', 'TLSv1': '#00b8cc',
    'TCP': '#8b5cf6', 'UDP': '#f59e0b', 'QUIC': '#22c55e',
    'HTTP': '#ff9500', 'HTTP/JSON': '#ff9500', 'DNS': '#6ec6ff',
    'SSLv2': '#ff6b9d', 'SSL': '#ff6b9d', 'SSHv2': '#c5e1a5', 'SSH': '#c5e1a5',
    'ICMP': '#fff59d', 'ICMPv6': '#fff59d', 'ARP': '#ffcc80',
    'MDNS': '#80deea', 'NTP': '#b39ddb', 'DHCP': '#ef9a9a',
}
const protoColor = (p) => PROTO_COLORS[p] || '#7d8590'

// Tag → color/label config
const TAG_CONFIG = {
    beaconing: { color: '#ef4444', Icon: Timer, label: 'Beaconing' },
    data_exfil: { color: '#ea580c', Icon: ShieldAlert, label: 'Data Exfil' },
    traffic_anomaly: { color: '#f59e0b', Icon: Zap, label: 'Anomaly' },
    new_dest: { color: '#3b82f6', Icon: MapPin, label: 'New Dest' },
}

const DirectionBadge = ({ dir }) => {
    const isIn = dir === 'INCOMING'
    return (
        <span className={`badge-direction ${isIn ? 'in' : 'out'}`}>
            {isIn ? '↓ IN' : '↑ OUT'}
        </span>
    )
}

const ProtoBadge = ({ proto }) => {
    const color = protoColor(proto)
    return (
        <span className="badge-proto" style={{ color, background: `${color}15`, border: `1px solid ${color}35` }}>
            {proto}
        </span>
    )
}

const TagBadge = ({ tag }) => {
    const cfg = TAG_CONFIG[tag]
    if (!cfg) return <span className="text-muted text-xs">—</span>
    const { Icon } = cfg
    return (
        <span className="badge" style={{ color: cfg.color, background: `${cfg.color}12`, border: `1px solid ${cfg.color}30` }}>
            <Icon size={12} />
            {cfg.label}
        </span>
    )
}

// ── Truncate long IPs (IPv6) with native tooltip ──
const IpCell = ({ value }) => {
    if (!value) return <span className="td-muted">—</span>
    const MAX = 22
    if (value.length <= MAX) return <span className="td-ip">{value}</span>
    return <span className="td-ip" title={value}>{value.slice(0, MAX)}…</span>
}

// ── Sortable column header ──
const SortHeader = ({ label, field, sortCol, sortDir, onSort }) => {
    const active = sortCol === field
    return (
        <th className={`th-sort${active ? ' th-sort-active' : ''}`} onClick={() => onSort(field)}>
            <span>{label}</span>
            {active ? (
                sortDir === 'asc' ? <ArrowUp size={12} /> : <ArrowDown size={12} />
            ) : (
                <ArrowUpDown size={12} className="th-sort-idle" />
            )}
        </th>
    )
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

    // Sorting (client-side on current page)
    const [sortCol, setSortCol] = useState('')
    const [sortDir, setSortDir] = useState('asc')

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

    const toggleExpand = (id) => {
        setExpanded(prev => {
            if (prev === id) {
                // Collapsing — clear AI state for this connection
                setAiAnalysis(p => { const n = { ...p }; delete n[id]; return n })
                setAiLoading(p => { const n = { ...p }; delete n[id]; return n })
                return null
            }
            return id
        })
    }

    const handleSort = (field) => {
        if (sortCol === field) {
            setSortDir(d => d === 'asc' ? 'desc' : 'asc')
        } else {
            setSortCol(field)
            setSortDir('asc')
        }
    }

    const sortedConnections = useMemo(() => {
        if (!sortCol) return connections
        return [...connections].sort((a, b) => {
            let av = a[sortCol], bv = b[sortCol]
            // numeric fields
            if (sortCol === 'packets') { av = Number(av) || 0; bv = Number(bv) || 0 }
            else if (sortCol === 'time') { av = av || ''; bv = bv || '' }
            else { av = String(av || '').toLowerCase(); bv = String(bv || '').toLowerCase() }
            if (av < bv) return sortDir === 'asc' ? -1 : 1
            if (av > bv) return sortDir === 'asc' ? 1 : -1
            return 0
        })
    }, [connections, sortCol, sortDir])

    const fmtTime = (isoStr) => {
        if (!isoStr) return '—'
        const d = new Date(isoStr)
        const pad = n => String(n).padStart(2, '0')
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    }

    // Calculate result range text
    const rangeStart = (page - 1) * perPage + 1
    const rangeEnd = Math.min(page * perPage, totalCount)

    const handleAnalyze = (c, e) => {
        e.stopPropagation()
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
                setAiAnalysis(prev => ({ ...prev, [c.id]: 'Failed to get AI analysis. Please try again.' }))
                setAiLoading(prev => ({ ...prev, [c.id]: false }))
            })
    }

    const handleReanalyze = (c, e) => {
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
                no_cache: true,
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
    }

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
                <button onClick={fetchConnections} className="btn-primary">
                    <RefreshCw size={13} />
                    Refresh
                </button>
            </div>

            <FilterBar
                search={search}
                onSearchChange={setSearch}
                searchPlaceholder="Search IP address or protocol…"
                proto={proto}
                onProtoChange={setProto}
                protocols={allProtocols}
                protoActiveColor="#3b82f6"
                perPage={perPage}
                onPerPageChange={setPerPage}
                dateFrom={dateFrom}
                dateTo={dateTo}
                onDateFromChange={setDateFrom}
                onDateToChange={setDateTo}
            >
                {/* Connections-specific: Tag dropdown + Port input */}
                <div className="icon-select-wrap">
                    <Tag size={14} className="form-input-icon" />
                    <select value={tag} onChange={e => setTag(e.target.value)}
                        className="form-select" style={{ paddingLeft: '2.2rem', color: tag ? (TAG_CONFIG[tag]?.color || '#f59e0b') : undefined }}>
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
                    className="form-input"
                    style={{ width: '90px', textAlign: 'center' }}
                />
            </FilterBar>

            {/* ── Table ── */}
            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                {loading ? (
                    <SkeletonTable rows={10} cols={8} />
                ) : connections.length === 0 ? (
                    <div className="panel">
                        <EmptyState
                            icon={Unplug}
                            title="No connections found"
                            description={search || proto || tag || dateFrom || dateTo
                                ? 'Try adjusting your filters or broadening your search criteria.'
                                : 'Start a capture session to see network connections here.'}
                        />
                    </div>
                ) : (
                    <div className="table-scroll">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Source</th>
                                    <th>Destination</th>
                                    <th>Protocol</th>
                                    <SortHeader label="Direction" field="direction" sortCol={sortCol} sortDir={sortDir} onSort={handleSort} />
                                    <SortHeader label="Packets" field="packets" sortCol={sortCol} sortDir={sortDir} onSort={handleSort} />
                                    <SortHeader label="Bytes" field="bytes" sortCol={sortCol} sortDir={sortDir} onSort={handleSort} />
                                    <th>Tags</th>
                                    <SortHeader label="Time" field="time" sortCol={sortCol} sortDir={sortDir} onSort={handleSort} />
                                </tr>
                            </thead>
                            <tbody>
                                {sortedConnections.map((c, rowIdx) => (
                                    <>
                                        <tr
                                            key={c.id}
                                            className={rowIdx % 2 === 1 ? 'tr-stripe' : undefined}
                                            onClick={() => toggleExpand(c.id)}
                                            style={{
                                                background: expanded === c.id
                                                    ? 'rgba(59,130,246,0.05)'
                                                    : c.tags
                                                        ? `${TAG_CONFIG[c.tags]?.color || '#f59e0b'}08`
                                                        : undefined,
                                            }}
                                        >
                                            <td><IpCell value={c.src} /></td>
                                            <td><IpCell value={c.dst} /></td>
                                            <td><ProtoBadge proto={c.protocol} /></td>
                                            <td><DirectionBadge dir={c.direction} /></td>
                                            <td className="td-num">{c.packets.toLocaleString()}</td>
                                            <td className="td-num">{c.bytes}</td>
                                            <td><TagBadge tag={c.tags} /></td>
                                            <td className="td-time">{fmtTime(c.time)}</td>
                                        </tr>
                                        {expanded === c.id && (
                                            <tr key={`${c.id}-detail`} className="detail-row">
                                                <td colSpan={8}>
                                                    <div className="detail-grid">
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
                                                            <div key={label} className="detail-item">
                                                                <div className="detail-item-label">{label}</div>
                                                                <div className="detail-item-value" style={{ fontFamily: typeof val === 'string' && val.includes('.') ? 'monospace' : 'inherit' }}>{val}</div>
                                                            </div>
                                                        ))}
                                                    </div>

                                                    {/* ── AI Analyze Button ── */}
                                                    <div className="detail-divider">
                                                        {!aiAnalysis[c.id] && !aiLoading[c.id] && (
                                                            <button onClick={(e) => handleAnalyze(c, e)} className="ai-btn">
                                                                <Sparkles size={14} style={{ marginRight: '0.35rem', verticalAlign: 'middle' }} /> Analyze Connection
                                                            </button>
                                                        )}

                                                        {aiLoading[c.id] && (
                                                            <div className="ai-loading">
                                                                <div className="spinner" />
                                                                Analyzing connection with AI...
                                                            </div>
                                                        )}

                                                        {aiAnalysis[c.id] && !aiLoading[c.id] && (
                                                            <div className="ai-panel">
                                                                <div className="ai-panel-header">
                                                                    <Sparkles size={14} style={{ marginRight: '0.35rem', verticalAlign: 'middle' }} /> AI Connection Analysis
                                                                    <button onClick={(e) => { e.stopPropagation(); setAiAnalysis(prev => { const next = { ...prev }; delete next[c.id]; return next }) }} className="btn-ghost" style={{ marginLeft: 'auto', padding: '2px 6px', fontSize: '0.7rem', color: '#7d8590' }}><X size={14} /></button>
                                                                </div>
                                                                <div className="ai-panel-body">
                                                                    {aiAnalysis[c.id].split('**').map((part, idx) =>
                                                                        idx % 2 === 1
                                                                            ? <strong key={idx} style={{ color: '#a0e8ff' }}>{part}</strong>
                                                                            : <span key={idx}>{part}</span>
                                                                    )}
                                                                </div>
                                                                <div className="ai-panel-footer">
                                                                    <span>Powered by Groq AI</span>
                                                                    <button onClick={(e) => handleReanalyze(c, e)}>Re-analyze</button>
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
                    <div className="pagination-bar">
                        <span>
                            Showing <span className="text-white">{rangeStart.toLocaleString()}–{rangeEnd.toLocaleString()}</span> of{' '}
                            <span className="text-white">{totalCount.toLocaleString()}</span> connections
                        </span>

                        <div className="pagination-controls">
                            <button onClick={() => setPage(1)} disabled={page === 1} className="page-btn">
                                <ChevronsLeft size={14} />
                            </button>
                            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="page-btn">
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
                                        className={`page-btn${p === page ? ' active' : ''}`}>
                                        {p}
                                    </button>
                                ))
                            })()}

                            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="page-btn">
                                <ChevronRight size={14} />
                            </button>
                            <button onClick={() => setPage(totalPages)} disabled={page === totalPages} className="page-btn">
                                <ChevronsRight size={14} />
                            </button>

                            <span className="pagination-info">
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
