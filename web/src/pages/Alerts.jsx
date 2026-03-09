import { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
    Zap, AlertTriangle, Search, RefreshCw, Filter,
    ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
    Layers, List, Radio, ExternalLink, ShieldOff, Sparkles, Globe, X
} from 'lucide-react'
import { useSession } from '../context/SessionContext'
import { SkeletonTable, EmptyState } from '../components/Skeleton'
import FilterBar from '../components/FilterBar'

const API = 'http://localhost:8000'

// ── Module-level cache for instant tab switches ──
const _alertsCache = new Map()

// ── Severity configuration ──
const SEV_CONFIG = {
    high: {
        color: '#ef4444', glow: 'rgba(239,68,68,0.15)',
        bg: 'rgba(239,68,68,0.06)', border: 'rgba(239,68,68,0.2)',
        label: 'CRITICAL', icon: AlertTriangle,
    },
    medium: {
        color: '#f59e0b', glow: 'rgba(245,158,11,0.15)',
        bg: 'rgba(245,158,11,0.06)', border: 'rgba(245,158,11,0.2)',
        label: 'WARNING', icon: AlertTriangle,
    },
    low: {
        color: '#3b82f6', glow: 'rgba(59,130,246,0.12)',
        bg: 'rgba(59,130,246,0.05)', border: 'rgba(59,130,246,0.18)',
        label: 'INFO', icon: AlertTriangle,
    },
}

// ── Severity stat card ──
const SevCard = ({ label, count, sev, active, onClick }) => {
    const cfg = SEV_CONFIG[sev]
    const Icon = cfg.icon
    return (
        <div
            onClick={onClick}
            className="sev-card"
            style={{
                background: active
                    ? `linear-gradient(135deg, ${cfg.bg}, rgba(10,10,16,0.6))`
                    : undefined,
                borderColor: active ? cfg.border : undefined,
                cursor: 'pointer',
            }}
        >
            {active && <div style={{
                position: 'absolute', top: '-50%', right: '-30%',
                width: '120px', height: '120px', borderRadius: '50%',
                background: `radial-gradient(circle, ${cfg.glow}, transparent 70%)`,
                pointerEvents: 'none',
            }} />}
            <div className="flex-between" style={{ marginBottom: '0.75rem' }}>
                <span className="sev-card-label" style={{ color: active ? cfg.color : '#7d8590' }}>{label}</span>
                <div style={{
                    width: '34px', height: '34px', borderRadius: '10px',
                    background: `${cfg.color}15`, border: `1px solid ${cfg.color}25`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                    <Icon size={16} color={cfg.color} />
                </div>
            </div>
            <div className="sev-card-value" style={{ color: active ? '#fff' : '#7d8590' }}>
                {count.toLocaleString()}
            </div>
        </div>
    )
}

// ── Category badge ──
const CategoryBadge = ({ category }) => {
    if (!category) return <span className="text-muted text-xs">—</span>
    return (
        <span className="badge" style={{
            padding: '3px 8px',
            background: 'rgba(139,92,246,0.08)', color: '#8b5cf6',
            border: '1px solid rgba(139,92,246,0.2)',
            maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis',
            display: 'inline-block',
        }}>
            {category}
        </span>
    )
}

// ── Action badge ──
const ActionBadge = ({ action }) => {
    const isBlocked = action === 'blocked'
    return (
        <span className="badge" style={{
            background: isBlocked ? 'rgba(239,68,68,0.12)' : 'rgba(34,197,94,0.08)',
            color: isBlocked ? '#ef4444' : '#22c55e',
            border: `1px solid ${isBlocked ? 'rgba(239,68,68,0.25)' : 'rgba(34,197,94,0.2)'}`,
            textTransform: 'uppercase',
        }}>
            {isBlocked ? '✕ BLOCKED' : '✓ ALLOWED'}
        </span>
    )
}

// ── Protocol badge ──
const PROTO_COLORS = {
    TCP: '#8b5cf6', UDP: '#f59e0b', ICMP: '#fff59d', GRE: '#80deea',
}
const ProtoBadge = ({ proto }) => {
    if (!proto) return null
    const color = PROTO_COLORS[proto] || '#7d8590'
    return (
        <span className="badge-proto" style={{ color, background: `${color}12`, border: `1px solid ${color}30` }}>
            {proto}
        </span>
    )
}

// ── Relative time helper ──
const relativeTime = (isoStr) => {
    if (!isoStr) return '—'
    const now = new Date()
    const d = new Date(isoStr)
    const diffMs = now - d
    const diffSec = Math.floor(diffMs / 1000)
    if (diffSec < 5) return 'just now'
    if (diffSec < 60) return `${diffSec}s ago`
    const diffMin = Math.floor(diffSec / 60)
    if (diffMin < 60) return `${diffMin}m ago`
    const diffHr = Math.floor(diffMin / 60)
    if (diffHr < 24) return `${diffHr}h ago`
    const diffDay = Math.floor(diffHr / 24)
    if (diffDay < 7) return `${diffDay}d ago`
    const pad = n => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

const fmtTime = (isoStr) => {
    if (!isoStr) return '—'
    const d = new Date(isoStr)
    const pad = n => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

// ═══════════════════════════════════════════════════════════════
// Alerts Page Component
// ═══════════════════════════════════════════════════════════════
const Alerts = () => {
    const { sessionId } = useSession()
    const [searchParams, setSearchParams] = useSearchParams()
    const cacheKey = `alerts-${sessionId || 0}`
    const cached = _alertsCache.get(cacheKey)

    const [alerts, setAlerts] = useState(cached?.alerts || [])
    const [loading, setLoading] = useState(!cached)
    const [isLive, setIsLive] = useState(false)

    // Counts
    const [totalCount, setTotalCount] = useState(cached?.totalCount || 0)
    const [highCount, setHighCount] = useState(cached?.highCount || 0)
    const [mediumCount, setMediumCount] = useState(cached?.mediumCount || 0)
    const [lowCount, setLowCount] = useState(cached?.lowCount || 0)
    const [allProtocols, setAllProtocols] = useState(cached?.protocols || [])
    const [totalPages, setTotalPages] = useState(cached?.totalPages || 1)

    // Filters
    const [search, setSearch] = useState(searchParams.get('search') || '')
    const [severity, setSeverity] = useState('')
    const [proto, setProto] = useState('')
    const [dateFrom, setDateFrom] = useState('')
    const [dateTo, setDateTo] = useState('')
    const [grouped, setGrouped] = useState(false)

    // Pagination
    const [page, setPage] = useState(1)
    const [perPage, setPerPage] = useState(50)

    // Expand
    const [expanded, setExpanded] = useState(null)
    const [aiExplanations, setAiExplanations] = useState({})
    const [aiLoading, setAiLoading] = useState({})
    const [ipCheck, setIpCheck] = useState({})
    const [ipLoading, setIpLoading] = useState({})

    // Live polling
    const intervalRef = useRef(null)

    const fetchAlerts = useCallback(async () => {
        if (!_alertsCache.has(cacheKey)) setLoading(true)
        try {
            const params = new URLSearchParams({
                page, per_page: perPage,
                severity, search, proto,
                date_from: dateFrom, date_to: dateTo,
                group: grouped,
            })
            if (sessionId) params.set('session_id', sessionId)
            const res = await fetch(`${API}/api/alerts?${params}`)
            const data = await res.json()
            setAlerts(data.alerts || [])
            setTotalCount(data.total_count || 0)
            setTotalPages(data.total_pages || 1)
            setHighCount(data.high_count || 0)
            setMediumCount(data.medium_count || 0)
            setLowCount(data.low_count || 0)
            setAllProtocols(data.protocols || [])
            if (!search && !severity && !proto && !dateFrom && !dateTo && !grouped && page === 1) {
                _alertsCache.set(cacheKey, {
                    alerts: data.alerts || [],
                    totalCount: data.total_count || 0,
                    totalPages: data.total_pages || 1,
                    highCount: data.high_count || 0,
                    mediumCount: data.medium_count || 0,
                    lowCount: data.low_count || 0,
                    protocols: data.protocols || [],
                })
            }
        } catch (e) { /* api offline */ }
        finally { setLoading(false) }
    }, [page, perPage, severity, search, proto, dateFrom, dateTo, grouped, sessionId, cacheKey])

    useEffect(() => {
        const checkLive = async () => {
            try {
                const res = await fetch(`${API}/api/capture/status`)
                const data = await res.json()
                setIsLive(data.state === 'capturing')
            } catch { setIsLive(false) }
        }
        checkLive()
        const id = setInterval(checkLive, 5000)
        return () => clearInterval(id)
    }, [])

    useEffect(() => {
        if (isLive) {
            intervalRef.current = setInterval(fetchAlerts, 5000)
        } else {
            if (intervalRef.current) clearInterval(intervalRef.current)
        }
        return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
    }, [isLive, fetchAlerts])

    useEffect(() => { setPage(1) }, [search, severity, proto, dateFrom, dateTo, perPage, grouped, sessionId])
    useEffect(() => { fetchAlerts() }, [fetchAlerts])

    // Auto-expand alert when navigated from Dashboard with ?alert_id=
    useEffect(() => {
        const alertId = searchParams.get('alert_id')
        const searchQ = searchParams.get('search')
        if (searchQ && search !== searchQ) setSearch(searchQ)
        if (alertId && alerts.length > 0) {
            const id = parseInt(alertId, 10)
            if (alerts.some(a => a.id === id)) {
                setExpanded(id)
                setSearchParams({}, { replace: true })
            }
        } else if (!alertId && searchQ) {
            setSearchParams({}, { replace: true })
        }
    }, [alerts, searchParams, setSearchParams])

    const toggleExpand = (id) => {
        setExpanded(prev => {
            if (prev === id) {
                // Collapsing — clear AI and IP state for this alert
                setAiExplanations(p => { const n = { ...p }; delete n[id]; return n })
                setAiLoading(p => { const n = { ...p }; delete n[id]; return n })
                setIpCheck(p => {
                    const n = { ...p }
                    delete n[`${id}_src`]
                    delete n[`${id}_dst`]
                    return n
                })
                setIpLoading(p => {
                    const n = { ...p }
                    delete n[`${id}_src`]
                    delete n[`${id}_dst`]
                    return n
                })
                return null
            }
            return id
        })
    }
    const toggleSeverityFilter = (sev) => setSeverity(prev => prev === sev ? '' : sev)


    const handleAiExplain = (a, e) => {
        e.stopPropagation()
        setAiLoading(prev => ({ ...prev, [a.id]: true }))
        fetch(`${API}/api/alerts/explain`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alert_id: a.id, signature: a.signature, category: a.category,
                severity: a.severity, src_ip: a.src_ip, dst_ip: a.dst_ip,
                src_port: a.src_port || 0, dst_port: a.dst_port || 0,
                proto: a.proto, action: a.action, timestamp: a.timestamp,
            }),
        })
            .then(r => r.json())
            .then(data => {
                setAiExplanations(prev => ({ ...prev, [a.id]: data.explanation || 'No explanation available.' }))
                setAiLoading(prev => ({ ...prev, [a.id]: false }))
            })
            .catch(() => {
                setAiExplanations(prev => ({ ...prev, [a.id]: 'Failed to get AI explanation. Please try again.' }))
                setAiLoading(prev => ({ ...prev, [a.id]: false }))
            })
    }

    const handleReExplain = (a, e) => {
        e.stopPropagation()
        setAiExplanations(prev => { const next = { ...prev }; delete next[a.id]; return next })
        setAiLoading(prev => ({ ...prev, [a.id]: true }))
        fetch(`${API}/api/alerts/explain`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alert_id: a.id, signature: a.signature, category: a.category,
                severity: a.severity, src_ip: a.src_ip, dst_ip: a.dst_ip,
                src_port: a.src_port || 0, dst_port: a.dst_port || 0,
                proto: a.proto, action: a.action, timestamp: a.timestamp,
                no_cache: true,
            }),
        })
            .then(r => r.json())
            .then(data => {
                setAiExplanations(prev => ({ ...prev, [a.id]: data.explanation || 'No explanation available.' }))
                setAiLoading(prev => ({ ...prev, [a.id]: false }))
            })
            .catch(() => {
                setAiExplanations(prev => ({ ...prev, [a.id]: 'Failed to get AI explanation. Please try again.' }))
                setAiLoading(prev => ({ ...prev, [a.id]: false }))
            })
    }

    const rangeStart = (page - 1) * perPage + 1
    const rangeEnd = Math.min(page * perPage, totalCount)
    const hasFilters = search || severity || proto || dateFrom || dateTo

    return (
        <>
            {/* ── Page Header ── */}
            <div className="page-header">
                <div>
                    <h1 className="page-title">Alerts</h1>
                    <p className="page-subtitle">
                        {totalCount.toLocaleString()} security events
                        {hasFilters && ' (filtered)'}
                    </p>
                </div>
                <div className="flex-row gap-lg">
                    {isLive && (
                        <div className="status-pill" style={{
                            background: 'rgba(239,68,68,0.08)',
                            border: '1px solid rgba(239,68,68,0.2)',
                            color: '#ff6b9d',
                        }}>
                            <Radio size={13} style={{ animation: 'pulseGlow 2s ease-in-out infinite' }} />
                            LIVE
                        </div>
                    )}
                    <button onClick={() => setGrouped(g => !g)}
                        className={grouped ? 'btn-violet' : 'btn-primary'}
                        style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem' }}>
                        {grouped ? <Layers size={13} /> : <List size={13} />}
                        {grouped ? 'Grouped' : 'Flat'}
                    </button>
                    <button onClick={fetchAlerts} className="btn-primary" style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem' }}>
                        <RefreshCw size={13} />
                        Refresh
                    </button>
                </div>
            </div>

            {/* ── Severity Summary Cards ── */}
            <div className="flex-row gap-lg flex-wrap" style={{ marginBottom: '1rem' }}>
                <SevCard label="Critical" count={highCount} sev="high"
                    active={severity === 'high'} onClick={() => toggleSeverityFilter('high')} />
                <SevCard label="Warning" count={mediumCount} sev="medium"
                    active={severity === 'medium'} onClick={() => toggleSeverityFilter('medium')} />
                <SevCard label="Informational" count={lowCount} sev="low"
                    active={severity === 'low'} onClick={() => toggleSeverityFilter('low')} />
            </div>

            <FilterBar
                search={search}
                onSearchChange={setSearch}
                searchPlaceholder="Search signature, IP address, or category…"
                proto={proto}
                onProtoChange={setProto}
                protocols={allProtocols}
                protoActiveColor="#ff6b9d"
                perPage={perPage}
                onPerPageChange={setPerPage}
                dateFrom={dateFrom}
                dateTo={dateTo}
                onDateFromChange={setDateFrom}
                onDateToChange={setDateTo}
                hasFilters={!!hasFilters}
                onClearAll={() => { setSearch(''); setSeverity(''); setProto(''); setDateFrom(''); setDateTo('') }}
            />

            {/* ── Alert Cards / Table ── */}
            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                {loading ? (
                    <SkeletonTable rows={8} cols={6} />
                ) : alerts.length === 0 ? (
                    <div className="panel">
                        <EmptyState
                            icon={ShieldOff}
                            title={hasFilters ? 'No alerts match these filters' : 'No security alerts recorded'}
                            description={hasFilters
                                ? 'Try adjusting your filter criteria or selecting a different time range.'
                                : 'Alerts from Suricata IDS and behavioral analysis will appear here during capture.'}
                        />
                    </div>
                ) : grouped ? (
                    /* ── Grouped View ── */
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                        {alerts.map((a, i) => {
                            const cfg = SEV_CONFIG[a.severity] || SEV_CONFIG.low
                            const Icon = cfg.icon
                            return (
                                <div key={i} style={{
                                    padding: '1rem 1.25rem',
                                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                                    borderLeft: `3px solid ${cfg.color}`,
                                    background: `linear-gradient(90deg, ${cfg.bg}, transparent 40%)`,
                                    cursor: 'default',
                                }}>
                                    <div className="flex-row" style={{ gap: '0.85rem', alignItems: 'flex-start' }}>
                                        <div style={{
                                            width: '36px', height: '36px', borderRadius: '10px', flexShrink: 0,
                                            background: `${cfg.color}15`, border: `1px solid ${cfg.color}30`,
                                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            marginTop: '2px',
                                        }}>
                                            <Icon size={16} color={cfg.color} />
                                        </div>

                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div className="flex-row gap-md flex-wrap" style={{ marginBottom: '0.3rem' }}>
                                                <span style={{
                                                    fontSize: '0.95rem', fontWeight: 600, color: '#e6edf3',
                                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                    maxWidth: '500px',
                                                }}>
                                                    {a.signature}
                                                </span>
                                                <span className="badge" style={{
                                                    padding: '2px 10px',
                                                    borderRadius: '10px', fontFamily: 'monospace',
                                                    background: `${cfg.color}18`, color: cfg.color,
                                                    border: `1px solid ${cfg.color}30`,
                                                }}>
                                                    ×{a.count}
                                                </span>
                                                <span className={`severity-badge ${a.severity}`}>
                                                    {cfg.label}
                                                </span>
                                            </div>
                                            <div className="flex-row gap-lg flex-wrap">
                                                <CategoryBadge category={a.category} />
                                                <ProtoBadge proto={a.proto} />
                                                <span className="text-xs" style={{ color: '#484f58' }}>First: {relativeTime(a.first_seen)}</span>
                                                <span className="text-xs" style={{ color: '#484f58' }}>Last: {relativeTime(a.last_seen)}</span>
                                            </div>
                                            {/* IPs */}
                                            <div className="flex-row flex-wrap" style={{ marginTop: '0.5rem', gap: '1.5rem' }}>
                                                {a.src_ips && a.src_ips[0] && (
                                                    <div>
                                                        <div className="detail-item-label">Sources</div>
                                                        <div className="td-muted" style={{ fontSize: '0.85rem', marginTop: '2px' }}>{a.src_ips.join(', ')}</div>
                                                    </div>
                                                )}
                                                {a.dst_ips && a.dst_ips[0] && (
                                                    <div>
                                                        <div className="detail-item-label">Destinations</div>
                                                        <div className="td-muted" style={{ fontSize: '0.85rem', marginTop: '2px' }}>{a.dst_ips.join(', ')}</div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )
                        })}
                    </div>
                ) : (
                    /* ── Flat View (individual alert cards) ── */
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                        {alerts.map((a, i) => {
                            const cfg = SEV_CONFIG[a.severity] || SEV_CONFIG.low
                            const Icon = cfg.icon
                            const isExpanded = expanded === a.id
                            return (
                                <div key={a.id}>
                                    <div
                                        onClick={() => toggleExpand(a.id)}
                                        style={{
                                            padding: '0.85rem 1.25rem',
                                            borderBottom: '1px solid rgba(255,255,255,0.04)',
                                            borderLeft: `3px solid ${cfg.color}`,
                                            background: isExpanded
                                                ? `linear-gradient(90deg, ${cfg.glow}, transparent 50%)`
                                                : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                                            cursor: 'pointer',
                                            transition: 'background 0.15s',
                                        }}
                                    >
                                        <div className="flex-row" style={{ gap: '0.85rem' }}>
                                            <div style={{
                                                width: '32px', height: '32px', borderRadius: '8px', flexShrink: 0,
                                                background: `${cfg.color}15`, border: `1px solid ${cfg.color}30`,
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            }}>
                                                <Icon size={14} color={cfg.color} />
                                            </div>

                                            <div style={{ flex: 1, minWidth: 0 }}>
                                                <div style={{
                                                    fontSize: '0.95rem', fontWeight: 600, color: '#e6edf3',
                                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                    marginBottom: '2px',
                                                }}>
                                                    {a.signature}
                                                </div>
                                                <div className="td-muted" style={{
                                                    fontSize: '0.85rem',
                                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                                }}>
                                                    {a.meta}
                                                </div>
                                            </div>

                                            <div className="flex-row" style={{ gap: '0.6rem', flexShrink: 0 }}>
                                                <CategoryBadge category={a.category} />
                                                <ProtoBadge proto={a.proto} />
                                                <ActionBadge action={a.action} />
                                                <span className={`severity-badge ${a.severity}`}>{cfg.label}</span>
                                                <span className="td-time" style={{ minWidth: '60px', textAlign: 'right' }}>
                                                    {relativeTime(a.timestamp)}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    {/* ── Expanded detail row ── */}
                                    {isExpanded && (
                                        <div style={{
                                            padding: '1rem 1.25rem 1.25rem 3.5rem',
                                            borderBottom: '1px solid rgba(255,255,255,0.06)',
                                            borderLeft: `3px solid ${cfg.color}`,
                                            background: `linear-gradient(135deg, ${cfg.bg}, transparent 60%)`,
                                        }}>
                                            <div className="detail-grid">
                                                {[
                                                    ['Alert ID', `#${a.id}`],
                                                    ['Signature', a.signature],
                                                    ['Category', a.category || '—'],
                                                    ['Severity', cfg.label],
                                                    ['Source IP', a.src_ip],
                                                    ['Source Port', a.src_port || '—'],
                                                    ['Destination IP', a.dst_ip],
                                                    ['Destination Port', a.dst_port || '—'],
                                                    ['Protocol', a.proto || '—'],
                                                    ['Action', a.action],
                                                    ['Timestamp', fmtTime(a.timestamp)],
                                                ].map(([label, val]) => (
                                                    <div key={label} className="detail-item">
                                                        <div className="detail-item-label" style={{ fontWeight: 600 }}>{label}</div>
                                                        <div className="detail-item-value" style={{
                                                            fontFamily: typeof val === 'string' && (val.includes('.') || val.includes(':')) ? 'monospace' : 'inherit',
                                                        }}>{val}</div>
                                                    </div>
                                                ))}
                                            </div>

                                            {/* ── AbuseIPDB IP Reputation ── */}
                                            <div className="detail-divider">
                                                <div className="detail-item-label" style={{ fontWeight: 600, marginBottom: '0.5rem' }}>
                                                    <Globe size={14} style={{ marginRight: '0.35rem', verticalAlign: 'middle' }} /> IP Reputation Check (AbuseIPDB)
                                                </div>
                                                <div className="flex-row gap-md flex-wrap">
                                                    {[['src', a.src_ip, 'Source'], ['dst', a.dst_ip, 'Destination']].map(([role, ip, label]) => {
                                                        if (!ip) return null
                                                        const key = `${a.id}_${role}`
                                                        const data = ipCheck[key]
                                                        const isLoading = ipLoading[key]

                                                        const doCheck = (e) => {
                                                            e.stopPropagation()
                                                            setIpLoading(prev => ({ ...prev, [key]: true }))
                                                            fetch(`${API}/api/ip/check/${encodeURIComponent(ip)}`)
                                                                .then(r => r.json())
                                                                .then(res => {
                                                                    setIpCheck(prev => ({ ...prev, [key]: res }))
                                                                    setIpLoading(prev => ({ ...prev, [key]: false }))
                                                                })
                                                                .catch(() => {
                                                                    setIpCheck(prev => ({ ...prev, [key]: { ok: false, error: 'Network error' } }))
                                                                    setIpLoading(prev => ({ ...prev, [key]: false }))
                                                                })
                                                        }

                                                        if (!data && !isLoading) {
                                                            return (
                                                                <button key={role} onClick={doCheck} className="btn-blue-sm" style={{
                                                                    background: 'rgba(245,158,11,0.08)',
                                                                    borderColor: 'rgba(245,158,11,0.2)',
                                                                    color: '#ccaa44',
                                                                }}>
                                                                    Check {label} IP
                                                                </button>
                                                            )
                                                        }

                                                        if (isLoading) {
                                                            return (
                                                                <div key={role} className="ai-loading" style={{ fontSize: '0.75rem' }}>
                                                                    <div className="spinner" style={{ width: '12px', height: '12px' }} />
                                                                    Checking {label.toLowerCase()}…
                                                                </div>
                                                            )
                                                        }

                                                        if (!data.ok) {
                                                            return (
                                                                <div key={role} style={{ fontSize: '0.75rem' }}>
                                                                    <span className="text-muted" style={{ fontWeight: 600 }}>{label}:</span>{' '}
                                                                    <span style={{ color: '#ff6b6b' }}>{data.error}</span>
                                                                    <button onClick={doCheck} className="btn-ghost" style={{ marginLeft: '8px' }}>↻ Retry</button>
                                                                    <button onClick={(e) => { e.stopPropagation(); setIpCheck(prev => { const next = { ...prev }; delete next[key]; return next }) }} className="btn-ghost" style={{ marginLeft: '8px', color: '#484f58' }}><X size={12} style={{ verticalAlign: 'middle' }} /> Close</button>
                                                                </div>
                                                            )
                                                        }

                                                        if (data.is_private) {
                                                            return (
                                                                <div key={role} style={{
                                                                    padding: '0.5rem 0.85rem', borderRadius: '8px',
                                                                    background: 'rgba(100,100,120,0.08)', border: '1px solid rgba(100,100,120,0.15)',
                                                                    fontSize: '0.75rem', minWidth: '220px',
                                                                }}>
                                                                    <div style={{ fontWeight: 600, color: '#7d8590', marginBottom: '4px' }}>{label}: <span className="mono">{ip}</span></div>
                                                                    <div className="text-muted">Private/local address — not internet-routable</div>
                                                                    <button onClick={(e) => { e.stopPropagation(); setIpCheck(prev => { const next = { ...prev }; delete next[key]; return next }) }} className="btn-ghost" style={{ marginTop: '4px', padding: 0, fontSize: '0.65rem', color: '#484f58' }}><X size={12} style={{ verticalAlign: 'middle' }} /> Close</button>
                                                                </div>
                                                            )
                                                        }

                                                        // Full result card
                                                        const score = data.abuse_score || 0
                                                        const clr = score > 50 ? '#ef4444' : score > 20 ? '#f59e0b' : '#22c55e'
                                                        return (
                                                            <div key={role} style={{
                                                                padding: '0.65rem 0.85rem', borderRadius: '10px',
                                                                background: `${clr}06`, border: `1px solid ${clr}20`,
                                                                minWidth: '260px', flex: 1, maxWidth: '400px',
                                                            }}>
                                                                <div className="flex-between" style={{ marginBottom: '0.5rem' }}>
                                                                    <div style={{ fontWeight: 600, color: '#c0c0c0', fontSize: '0.75rem' }}>
                                                                        {role === 'src' ? '⬆' : '⬇'} {label}: <span className="mono">{ip}</span>
                                                                    </div>
                                                                    <span className="badge" style={{
                                                                        background: `${clr}18`, color: clr,
                                                                        fontSize: '0.65rem',
                                                                    }}>
                                                                        {data.verdict || (score > 50 ? 'MALICIOUS' : score > 20 ? 'SUSPICIOUS' : 'CLEAN')}
                                                                    </span>
                                                                </div>

                                                                {/* Score bar */}
                                                                <div style={{ marginBottom: '0.5rem' }}>
                                                                    <div className="flex-between" style={{ fontSize: '0.65rem', color: '#7d8590', marginBottom: '3px' }}>
                                                                        <span>Abuse Confidence</span>
                                                                        <span style={{ color: clr, fontWeight: 700 }}>{score}%</span>
                                                                    </div>
                                                                    <div style={{ height: '4px', borderRadius: '2px', background: 'rgba(255,255,255,0.06)' }}>
                                                                        <div style={{ height: '100%', width: `${score}%`, borderRadius: '2px', background: clr, transition: 'width 0.4s ease' }} />
                                                                    </div>
                                                                </div>

                                                                {/* Details grid */}
                                                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 12px', fontSize: '0.7rem' }}>
                                                                    {data.country && <><span className="text-muted">Country</span><span className="text-muted">🌍 {data.country}</span></>}
                                                                    {data.isp && <><span className="text-muted">ISP</span><span className="text-muted" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{data.isp}</span></>}
                                                                    {data.domain && <><span className="text-muted">Domain</span><span className="text-muted">{data.domain}</span></>}
                                                                    {data.usage_type && <><span className="text-muted">Type</span><span className="text-muted">{data.usage_type}</span></>}
                                                                    {data.total_reports > 0 && <><span className="text-muted">Reports</span><span style={{ color: score > 50 ? '#ff6b6b' : '#7d8590', fontWeight: 600 }}>{data.total_reports} ({data.num_distinct_users || 0} users)</span></>}
                                                                    {data.is_tor && <><span className="text-muted">Tor</span><span style={{ color: '#f59e0b', fontWeight: 600 }}>⚠ Tor Exit Node</span></>}
                                                                    {data.is_whitelisted && <><span className="text-muted">Whitelist</span><span style={{ color: '#22c55e' }}>✓ Whitelisted</span></>}
                                                                </div>

                                                                <button onClick={doCheck} className="btn-ghost" style={{ marginTop: '6px', padding: 0, fontSize: '0.65rem', color: '#484f58' }}>↻ Re-check</button>
                                                                <button onClick={(e) => { e.stopPropagation(); setIpCheck(prev => { const next = { ...prev }; delete next[key]; return next }) }} className="btn-ghost" style={{ marginTop: '6px', marginLeft: '12px', padding: 0, fontSize: '0.65rem', color: '#484f58' }}><X size={12} style={{ verticalAlign: 'middle' }} /> Close</button>
                                                            </div>
                                                        )
                                                    })}
                                                </div>
                                            </div>

                                            {/* ── AI Explain Button ── */}
                                            <div className="detail-divider">
                                                {!aiExplanations[a.id] && !aiLoading[a.id] && (
                                                    <button onClick={(e) => handleAiExplain(a, e)} className="ai-btn">
                                                        <Sparkles size={14} style={{ marginRight: '0.35rem', verticalAlign: 'middle' }} /> Explain with AI
                                                    </button>
                                                )}

                                                {aiLoading[a.id] && (
                                                    <div className="ai-loading">
                                                        <div className="spinner" />
                                                        Analyzing alert with AI...
                                                    </div>
                                                )}

                                                {aiExplanations[a.id] && !aiLoading[a.id] && (
                                                    <div className="ai-panel">
                                                        <div className="ai-panel-header"><Sparkles size={14} style={{ marginRight: '0.35rem', verticalAlign: 'middle' }} /> AI Analysis<button onClick={(e) => { e.stopPropagation(); setAiExplanations(prev => { const next = { ...prev }; delete next[a.id]; return next }) }} className="btn-ghost" style={{ marginLeft: 'auto', padding: '2px 6px', fontSize: '0.7rem', color: '#7d8590' }}><X size={14} /></button></div>
                                                        <div className="ai-panel-body">
                                                            {aiExplanations[a.id].split('**').map((part, idx) =>
                                                                idx % 2 === 1
                                                                    ? <strong key={idx} style={{ color: '#e8d0ff' }}>{part}</strong>
                                                                    : <span key={idx}>{part}</span>
                                                            )}
                                                        </div>
                                                        <div className="ai-panel-footer">
                                                            <span>Powered by Groq AI</span>
                                                            <button onClick={(e) => handleReExplain(a, e)}>Re-analyze</button>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )
                        })}
                    </div>
                )}

                {/* ── Pagination Bar ── */}
                {totalCount > 0 && (
                    <div className="pagination-bar">
                        <span>
                            Showing <span className="text-white">{rangeStart.toLocaleString()}–{rangeEnd.toLocaleString()}</span> of{' '}
                            <span className="text-white">{totalCount.toLocaleString()}</span> alerts
                        </span>

                        <div className="pagination-controls">
                            <button onClick={() => setPage(1)} disabled={page === 1} className="page-btn">
                                <ChevronsLeft size={14} />
                            </button>
                            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="page-btn">
                                <ChevronLeft size={14} />
                            </button>

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

export default Alerts
