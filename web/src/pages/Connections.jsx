import { useState, useEffect, useCallback, useMemo } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Activity, RefreshCw, Tag, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, ArrowUp, ArrowDown, ArrowUpDown, Unplug, Sparkles, X, Timer, ShieldAlert, Zap, MapPin, Clock, ArrowRightLeft, Network, AlertTriangle, Globe, History, Layers, ExternalLink } from 'lucide-react'
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

// ── State badge for TCP connection state ──
const StateBadge = ({ state }) => {
    if (!state) return <span className="text-muted">—</span>
    const colors = {
        ACTIVE: '#22c55e', ESTABLISHED: '#22c55e', SYN_SENT: '#f59e0b',
        FIN: '#7d8590', RST: '#ef4444',
    }
    const color = colors[state] || '#7d8590'
    return (
        <span className="badge" style={{ color, background: `${color}15`, border: `1px solid ${color}30`, fontSize: '0.7rem' }}>
            {state}
        </span>
    )
}

// ── Severity badge ──
const SeverityBadge = ({ severity }) => {
    if (!severity) return null
    const colors = { critical: '#ef4444', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6' }
    const color = colors[severity.toLowerCase()] || '#7d8590'
    return (
        <span className="badge" style={{ color, background: `${color}15`, border: `1px solid ${color}30`, fontSize: '0.7rem', textTransform: 'uppercase' }}>
            {severity}
        </span>
    )
}

// ── Format duration to human-readable ──
const fmtDuration = (secs) => {
    if (!secs || secs <= 0) return '< 1s'
    if (secs < 60) return `${secs.toFixed(1)}s`
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${Math.floor(secs % 60)}s`
    const h = Math.floor(secs / 3600)
    const m = Math.floor((secs % 3600) / 60)
    return `${h}h ${m}m`
}

// ── Detail section header ──
const SectionHeader = ({ icon: Icon, title, count }) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', marginTop: '1.25rem' }}>
        <Icon size={14} style={{ color: '#3b82f6' }} />
        <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#c9d1d9', letterSpacing: '0.02em' }}>{title}</span>
        {count !== undefined && (
            <span style={{ fontSize: '0.7rem', color: '#7d8590', background: '#21262d', borderRadius: '10px', padding: '1px 8px' }}>{count}</span>
        )}
    </div>
)

// ── Enriched connection detail panel ──
const ConnectionDetailPanel = ({ c, details, fmtTime, aiAnalysis, aiLoading, onAnalyze, onReanalyze, setAiAnalysis, navigate }) => {
    const d = details?.connection || c
    const relatedAlerts = details?.related_alerts || []
    const reputation = details?.reputation || {}
    const destHistory = details?.dest_history
    const relatedConns = details?.related_connections || []

    return (
        <div style={{ padding: '0.25rem 0' }}>
            {/* ── Connection Info + Flow Metrics (merged, only essential) ── */}
            <SectionHeader icon={Network} title="Connection Details" />
            <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))' }}>
                <div className="detail-item">
                    <div className="detail-item-label">Source</div>
                    <div className="detail-item-value" style={{ fontFamily: 'monospace' }}>{d.src_ip}{d.src_port ? `:${d.src_port}` : ''}</div>
                </div>
                <div className="detail-item">
                    <div className="detail-item-label">Destination</div>
                    <div className="detail-item-value" style={{ fontFamily: 'monospace' }}>{d.dst_ip}{d.dst_port ? `:${d.dst_port}` : ''}</div>
                </div>
                {[
                    ['Protocol', d.protocol],
                    ['Direction', d.direction],
                    ['Packets', (d.packets || 0).toLocaleString()],
                    ['Data', d.bytes || c.bytes],
                    ['Duration', fmtDuration(d.duration)],
                    ['Data Rate', d.data_rate || '—'],
                    ['Started', fmtTime(d.start_time || d.time || c.time)],
                ].map(([label, val]) => (
                    <div key={label} className="detail-item">
                        <div className="detail-item-label">{label}</div>
                        <div className="detail-item-value">{val}</div>
                    </div>
                ))}
                {d.severity && (
                    <div className="detail-item">
                        <div className="detail-item-label">Severity</div>
                        <div className="detail-item-value"><SeverityBadge severity={d.severity} /></div>
                    </div>
                )}
                {d.tags && (
                    <div className="detail-item">
                        <div className="detail-item-label">Tags</div>
                        <div className="detail-item-value" style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                            {d.tags.split(',').map(t => t.trim()).filter(Boolean).map(t => <TagBadge key={t} tag={t} />)}
                        </div>
                    </div>
                )}
            </div>

            {/* ── Section 3: IP Reputation ── */}
            {Object.keys(reputation).length > 0 && (
                <>
                    <SectionHeader icon={Globe} title="IP Reputation" count={Object.keys(reputation).length} />
                    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                        {Object.entries(reputation).map(([ip, rep]) => {
                            const scoreColor = rep.abuse_score >= 50 ? '#ef4444' : rep.abuse_score >= 20 ? '#f59e0b' : '#22c55e'
                            return (
                                <div key={ip} style={{
                                    background: '#161b22', border: '1px solid #30363d', borderRadius: '8px',
                                    padding: '0.75rem 1rem', flex: '1 1 220px', minWidth: '220px'
                                }}>
                                    <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#c9d1d9', marginBottom: '0.5rem' }}>{ip}</div>
                                    <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', fontSize: '0.75rem' }}>
                                        <div>
                                            <span style={{ color: '#7d8590' }}>Abuse Score </span>
                                            <span style={{ color: scoreColor, fontWeight: 700 }}>{rep.abuse_score}%</span>
                                        </div>
                                        {rep.country && <div><span style={{ color: '#7d8590' }}>Country </span><span style={{ color: '#c9d1d9' }}>{rep.country}</span></div>}
                                        {rep.isp && <div><span style={{ color: '#7d8590' }}>ISP </span><span style={{ color: '#c9d1d9' }}>{rep.isp}</span></div>}
                                        {rep.is_malicious && <span className="badge" style={{ color: '#ef4444', background: '#ef444415', border: '1px solid #ef444430', fontSize: '0.65rem' }}>MALICIOUS</span>}
                                    </div>
                                </div>
                            )
                        })}
                    </div>
                </>
            )}

            {/* ── Section 4: Destination History ── */}
            {destHistory && (
                <>
                    <SectionHeader icon={History} title="Destination History" />
                    <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))' }}>
                        <div className="detail-item">
                            <div className="detail-item-label">First Seen</div>
                            <div className="detail-item-value">{fmtTime(destHistory.first_seen)}</div>
                        </div>
                        <div className="detail-item">
                            <div className="detail-item-label">Sessions Observed</div>
                            <div className="detail-item-value">{destHistory.session_count}</div>
                        </div>
                        <div className="detail-item">
                            <div className="detail-item-label">Avg Data/Session</div>
                            <div className="detail-item-value">{destHistory.avg_bytes}</div>
                        </div>
                    </div>
                </>
            )}

            {/* ── Related Alerts (clickable → navigates to Alerts page) ── */}
            {relatedAlerts.length > 0 && (
                <>
                    <SectionHeader icon={AlertTriangle} title="Related Alerts" count={relatedAlerts.length} />
                    <div style={{ maxHeight: '200px', overflowY: 'auto', borderRadius: '6px', border: '1px solid #30363d' }}>
                        <table style={{ width: '100%', fontSize: '0.75rem', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr style={{ background: '#161b22', position: 'sticky', top: 0 }}>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Time</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Severity</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Signature</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Category</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'center', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d', width: '40px' }}></th>
                                </tr>
                            </thead>
                            <tbody>
                                {relatedAlerts.map(a => (
                                    <tr key={a.id}
                                        onClick={(e) => { e.stopPropagation(); navigate(`/alerts?alert_id=${a.id}&search=${encodeURIComponent(d.dst_ip)}`) }}
                                        style={{ borderBottom: '1px solid #21262d', cursor: 'pointer', transition: 'background 0.15s' }}
                                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(59,130,246,0.06)'}
                                        onMouseLeave={e => e.currentTarget.style.background = ''}
                                    >
                                        <td style={{ padding: '0.35rem 0.6rem', color: '#7d8590', whiteSpace: 'nowrap' }}>{fmtTime(a.timestamp)}</td>
                                        <td style={{ padding: '0.35rem 0.6rem' }}><SeverityBadge severity={a.severity} /></td>
                                        <td style={{ padding: '0.35rem 0.6rem', color: '#c9d1d9', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.signature}>{a.signature}</td>
                                        <td style={{ padding: '0.35rem 0.6rem', color: '#7d8590' }}>{a.category || '—'}</td>
                                        <td style={{ padding: '0.35rem 0.6rem', textAlign: 'center' }}><ExternalLink size={12} style={{ color: '#3b82f6' }} /></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </>
            )}

            {/* ── Other Connections to Same Destination (clickable → searches that IP) ── */}
            {relatedConns.length > 0 && (
                <>
                    <SectionHeader icon={Layers} title="Other Connections to This Destination" count={relatedConns.length} />
                    <div style={{ maxHeight: '180px', overflowY: 'auto', borderRadius: '6px', border: '1px solid #30363d' }}>
                        <table style={{ width: '100%', fontSize: '0.75rem', borderCollapse: 'collapse' }}>
                            <thead>
                                <tr style={{ background: '#161b22', position: 'sticky', top: 0 }}>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Source</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Protocol</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Packets</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Data</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Tags</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d' }}>Time</th>
                                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'center', color: '#7d8590', fontWeight: 500, borderBottom: '1px solid #30363d', width: '40px' }}></th>
                                </tr>
                            </thead>
                            <tbody>
                                {relatedConns.map(rc => (
                                    <tr key={rc.id}
                                        onClick={(e) => { e.stopPropagation(); navigate(`/connections?conn_id=${rc.id}&search=${encodeURIComponent(rc.dst_ip)}`) }}
                                        style={{ borderBottom: '1px solid #21262d', cursor: 'pointer', transition: 'background 0.15s' }}
                                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(59,130,246,0.06)'}
                                        onMouseLeave={e => e.currentTarget.style.background = ''}
                                    >
                                        <td style={{ padding: '0.35rem 0.6rem', fontFamily: 'monospace', color: '#c9d1d9', fontSize: '0.7rem' }}>{rc.src_ip}{rc.src_port ? `:${rc.src_port}` : ''}</td>
                                        <td style={{ padding: '0.35rem 0.6rem' }}><ProtoBadge proto={rc.protocol} /></td>
                                        <td style={{ padding: '0.35rem 0.6rem', color: '#c9d1d9' }}>{rc.packets.toLocaleString()}</td>
                                        <td style={{ padding: '0.35rem 0.6rem', color: '#c9d1d9' }}>{rc.bytes}</td>
                                        <td style={{ padding: '0.35rem 0.6rem' }}>{rc.tags ? <TagBadge tag={rc.tags} /> : <span style={{ color: '#484f58' }}>—</span>}</td>
                                        <td style={{ padding: '0.35rem 0.6rem', color: '#7d8590', whiteSpace: 'nowrap' }}>{fmtTime(rc.time)}</td>
                                        <td style={{ padding: '0.35rem 0.6rem', textAlign: 'center' }}><ExternalLink size={12} style={{ color: '#3b82f6' }} /></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </>
            )}

            {/* ── AI Analyze Button ── */}
            <div className="detail-divider">
                {!aiAnalysis[c.id] && !aiLoading[c.id] && (
                    <button onClick={(e) => onAnalyze(c, e)} className="ai-btn">
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
                            <button onClick={(e) => onReanalyze(c, e)}>Re-analyze</button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}

const Connections = () => {
    const { sessionId } = useSession()
    const navigate = useNavigate()
    const [searchParams, setSearchParams] = useSearchParams()
    const cacheKey = `connections-${sessionId || 0}`
    const cached = _connCache.get(cacheKey)

    const [connections, setConnections] = useState(cached?.connections || [])
    const [allProtocols, setAllProtocols] = useState(cached?.protocols || [])
    const [allTags, setAllTags] = useState(cached?.tags || [])
    const [totalCount, setTotalCount] = useState(cached?.totalCount || 0)
    const [totalPages, setTotalPages] = useState(cached?.totalPages || 1)
    const [loading, setLoading] = useState(!cached)

    // Filters
    const [search, setSearch] = useState(searchParams.get('search') || '')
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
    const [connDetails, setConnDetails] = useState({})
    const [detailsLoading, setDetailsLoading] = useState({})

    // Handle incoming URL params (cross-links from related connections / alerts)
    useEffect(() => {
        const connId = searchParams.get('conn_id')
        const searchQ = searchParams.get('search')
        if (searchQ && search !== searchQ) setSearch(searchQ)
        if (connId && connections.length > 0) {
            const id = parseInt(connId, 10)
            if (connections.some(c => c.id === id)) {
                setExpanded(id)
                // Fetch details for this connection
                if (!connDetails[id]) {
                    setDetailsLoading(p => ({ ...p, [id]: true }))
                    fetch(`${API}/api/connections/${id}/details`)
                        .then(r => r.json())
                        .then(data => {
                            if (data.ok) setConnDetails(p => ({ ...p, [id]: data }))
                            setDetailsLoading(p => ({ ...p, [id]: false }))
                        })
                        .catch(() => setDetailsLoading(p => ({ ...p, [id]: false })))
                }
                setSearchParams({}, { replace: true })
            }
        } else if (connId && connections.length === 0) {
            // connections not loaded yet — keep params, will retry on next render
        } else if (!connId && searchQ) {
            setSearchParams({}, { replace: true })
        }
    }, [connections, searchParams])

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
            // Expanding — fetch enriched details if not already cached
            if (!connDetails[id]) {
                setDetailsLoading(p => ({ ...p, [id]: true }))
                fetch(`${API}/api/connections/${id}/details`)
                    .then(r => r.json())
                    .then(data => {
                        if (data.ok) {
                            setConnDetails(p => ({ ...p, [id]: data }))
                        }
                        setDetailsLoading(p => ({ ...p, [id]: false }))
                    })
                    .catch(() => setDetailsLoading(p => ({ ...p, [id]: false })))
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
                <button onClick={fetchConnections} className="btn-primary" style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem' }}>
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
                                                    {detailsLoading[c.id] && !connDetails[c.id] ? (
                                                        <div style={{ padding: '1.5rem', textAlign: 'center', color: '#7d8590' }}>
                                                            <div className="spinner" style={{ margin: '0 auto 0.5rem' }} />
                                                            Loading connection details…
                                                        </div>
                                                    ) : (
                                                        <ConnectionDetailPanel
                                                            c={c}
                                                            details={connDetails[c.id]}
                                                            fmtTime={fmtTime}
                                                            aiAnalysis={aiAnalysis}
                                                            aiLoading={aiLoading}
                                                            onAnalyze={handleAnalyze}
                                                            onReanalyze={handleReanalyze}
                                                            setAiAnalysis={setAiAnalysis}
                                                            navigate={navigate}
                                                        />
                                                    )}
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
