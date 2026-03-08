import { useState, useEffect, useCallback } from 'react'
import { createPortal } from 'react-dom'
import {
    Settings as SettingsIcon, CheckCircle, XCircle, Shield, HardDrive,
    Database, Trash2, RefreshCw, Monitor, Cpu, AlertTriangle,
    FileText, Clock, Activity, ChevronDown, ChevronRight, Info,
    Play, Square, Download, MoreHorizontal, X,
    ChevronLeft, ChevronsLeft, ChevronsRight
} from 'lucide-react'
import { useSession } from '../context/SessionContext'
import { useApiCache } from '../hooks/useApiCache'

const API = 'http://localhost:8000'

// ── Status pill component ──
const StatusPill = ({ ok, label }) => (
    <div className={`status-pill ${ok ? 'available' : 'missing'}`}>
        {ok ? <CheckCircle size={12} /> : <XCircle size={12} />}
        {label || (ok ? 'Available' : 'Not Found')}
    </div>
)

// ── Dependency row ──
const DepRow = ({ name, icon, installed, version, extra }) => (
    <div className="flex-row gap-lg" style={{
        padding: '0.85rem 1.25rem',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
    }}>
        <div style={{
            width: '36px', height: '36px', borderRadius: '10px', flexShrink: 0,
            background: installed ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.06)',
            border: `1px solid ${installed ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)'}`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: installed ? '#22c55e' : '#ef4444',
        }}>
            {icon}
        </div>
        <div style={{ flex: 1 }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#e6edf3' }}>{name}</div>
            {version && <div className="td-muted text-xs">{version}</div>}
            {extra && <div className="text-muted text-xs">{extra}</div>}
        </div>
        <StatusPill ok={installed} />
    </div>
)

// ── Data stat box ──
const DataBox = ({ label, value, sub, color, icon }) => (
    <div className="stat-box">
        <div className="flex-between" style={{ marginBottom: '0.6rem' }}>
            <span className="stat-box-label">{label}</span>
            <div style={{
                width: '32px', height: '32px', borderRadius: '8px',
                background: `${color}12`, border: `1px solid ${color}20`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color,
            }}>{icon}</div>
        </div>
        <div className="stat-box-value" style={{ color: '#fff', textAlign: 'left' }}>{value}</div>
        {sub && <div className="stat-box-sub" style={{ textAlign: 'left' }}>{sub}</div>}
    </div>
)

// ═══════════════════════════════════════════════════════════════
// Settings Page
// ═══════════════════════════════════════════════════════════════
const Settings = () => {
    const [clearing, setClearing] = useState(false)
    const [deletingSession, setDeletingSession] = useState(null)
    const [expandedSession, setExpandedSession] = useState(null)
    const [menuOpen, setMenuOpen] = useState(null)
    const [confirmModal, setConfirmModal] = useState(null) // { type, sessionId, message }
    const [sessPage, setSessPage] = useState(1)
    const sessPerPage = 15
    const { sessionId, loadSession, unloadSession } = useSession()

    const { data: system, refresh: refreshSystem } = useApiCache(
        'settings-system',
        async () => {
            const res = await fetch(`${API}/api/settings/system`)
            return res.json()
        },
        { fallback: null }
    )

    const { data: data, loading, refresh: refreshData } = useApiCache(
        'settings-data',
        async () => {
            const res = await fetch(`${API}/api/settings/data`)
            return res.json()
        },
        { fallback: null }
    )

    const fetchData = useCallback(() => {
        refreshSystem()
        refreshData()
    }, [refreshSystem, refreshData])

    const handleClearAll = async () => {
        setClearing(true)
        setConfirmModal(null)
        try {
            const res = await fetch(`${API}/api/settings/clear`, { method: 'POST' })
            const result = await res.json()
            if (result.ok) fetchData()
        } catch (e) { /* */ }
        finally { setClearing(false) }
    }

    const handleDeleteSession = async (sid) => {
        setDeletingSession(sid)
        setConfirmModal(null)
        try {
            const res = await fetch(`${API}/api/settings/sessions/${sid}`, { method: 'DELETE' })
            const result = await res.json()
            if (result.ok) fetchData()
        } catch (e) { /* */ }
        finally { setDeletingSession(null) }
    }

    const requestDeleteSession = (sid, e) => {
        e.stopPropagation()
        setMenuOpen(null)
        setConfirmModal({
            type: 'delete-session',
            sessionId: sid,
            title: 'Delete Session',
            message: `Are you sure you want to delete session #${sid}? This will remove all packets, connections, and alerts for this session.`,
            confirmLabel: 'Delete Session',
            onConfirm: () => handleDeleteSession(sid),
        })
    }

    const requestClearAll = () => {
        setConfirmModal({
            type: 'clear-all',
            title: 'Clear All Sessions',
            message: 'This will permanently delete all sessions, connections, alerts, and capture files. This action cannot be undone.',
            confirmLabel: 'Yes, Delete Everything',
            onConfirm: handleClearAll,
        })
    }

    const fmtTime = (isoStr) => {
        if (!isoStr) return '—'
        const d = new Date(isoStr)
        const pad = n => String(n).padStart(2, '0')
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    }

    if (loading && !system) {
        return (
            <>
                <div className="page-header">
                    <div>
                        <h1 className="page-title">Settings</h1>
                        <p className="page-subtitle">Configuration and system status</p>
                    </div>
                </div>
                <div className="panel loading-state">
                    <SettingsIcon size={32} className="icon" />
                    <p>Loading system information…</p>
                </div>
            </>
        )
    }

    const sessions = data?.sessions || []
    const sessTotalPages = Math.max(1, Math.ceil(sessions.length / sessPerPage))
    const sessStart = (sessPage - 1) * sessPerPage
    const paginatedSessions = sessions.slice(sessStart, sessStart + sessPerPage)
    const sessRangeStart = sessions.length === 0 ? 0 : sessStart + 1
    const sessRangeEnd = Math.min(sessStart + sessPerPage, sessions.length)

    return (
        <>
            {/* ── Page Header ── */}
            <div className="page-header">
                <div>
                    <h1 className="page-title">Settings</h1>
                    <p className="page-subtitle">System status and data management</p>
                </div>
                <button onClick={fetchData} className="btn-violet" style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem' }}>
                    <RefreshCw size={13} />
                    Refresh
                </button>
            </div>

            {/* ── System Status Panel ── */}
            {system && (
                <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                    <div className="panel-header" style={{ padding: '1rem 1.25rem', marginBottom: 0 }}>
                        <span className="panel-title">
                            <Monitor size={16} style={{ color: '#22c55e' }} />
                            System Dependencies
                        </span>
                        <StatusPill ok={system.root} label={system.root ? 'Root Access' : 'No Root'} />
                    </div>

                    <DepRow name="TShark (Wireshark Engine)" icon={<Activity size={16} />}
                        installed={system.tshark.installed}
                        version={system.tshark.version ? `v${system.tshark.version}` : ''}
                        extra="Packet analysis and protocol dissection" />
                    <DepRow name="Dumpcap" icon={<HardDrive size={16} />}
                        installed={system.dumpcap.installed}
                        version={system.dumpcap.version ? `v${system.dumpcap.version}` : ''}
                        extra="Zero-drop packet capture engine" />
                    <DepRow name="Suricata IDS" icon={<Shield size={16} />}
                        installed={system.suricata.installed}
                        version={system.suricata.version || ''}
                        extra="Signature-based intrusion detection" />
                    <DepRow name="Suricata Rules" icon={<FileText size={16} />}
                        installed={system.suricata_rules.loaded}
                        version={system.suricata_rules.loaded ? `${system.suricata_rules.count.toLocaleString()} active rules` : ''}
                        extra={system.suricata_rules.loaded ? '/var/lib/suricata/rules/suricata.rules' : 'Run: sudo suricata-update'} />

                    <div className="flex-row gap-lg flex-wrap" style={{
                        padding: '0.75rem 1.25rem',
                        borderTop: '1px solid rgba(255,255,255,0.04)',
                        fontSize: '0.72rem', color: '#484f58',
                    }}>
                        <span>Python {system.python_version}</span>
                        <span>{system.os}</span>
                        <span>{system.machine}</span>
                    </div>
                </div>
            )}

            {/* ── Data Overview Cards ── */}
            {data && (
                <div className="flex-row gap-lg flex-wrap">
                    <DataBox label="Database" value={data.db_size_display}
                        sub={sessions.length + ' sessions'} color="#8b5cf6"
                        icon={<Database size={16} />} />
                    <DataBox label="Capture Files" value={data.pcap_total_display}
                        sub={data.pcap_count + ' pcapng files'} color="#3b82f6"
                        icon={<HardDrive size={16} />} />
                    <DataBox label="Total Sessions" value={sessions.length}
                        sub="Capture histories" color="#22c55e"
                        icon={<Cpu size={16} />} />
                </div>
            )}

            {/* ── Data Management Panel ── */}
            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                <div className="panel-header" style={{ padding: '1rem 1.25rem', marginBottom: 0 }}>
                    <span className="panel-title">
                        <Database size={16} style={{ color: '#8b5cf6' }} />
                        Data Management
                    </span>
                </div>

                <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <div className="flex-row gap-lg flex-wrap">
                        <button onClick={requestClearAll} disabled={clearing} className="btn-danger" style={{ padding: '0.55rem 1.1rem', fontSize: '0.8rem' }}>
                            <Trash2 size={14} />
                            {clearing ? 'Clearing…' : 'Clear All Sessions'}
                        </button>

                        <div style={{ flex: 1 }} />

                        {data && (
                            <span className="text-xs" style={{ color: '#484f58' }}>
                                DB: {data.db_size_display} &nbsp;·&nbsp; Captures: {data.pcap_total_display}
                            </span>
                        )}
                    </div>
                </div>

                {/* ── Session History Table ── */}
                <div>
                    {/* Table header */}
                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: '60px 1fr 140px 90px 90px 70px 70px 140px',
                        padding: '0.65rem 1.25rem',
                        borderBottom: '1px solid rgba(255,255,255,0.06)',
                        fontSize: '0.68rem', fontWeight: 600, color: '#484f58',
                        textTransform: 'uppercase', letterSpacing: '0.08em',
                    }}>
                        <span>ID</span><span>Started</span><span>Interface</span>
                        <span>Packets</span><span>Data</span><span>Alerts</span>
                        <span>Flows</span><span>Actions</span>
                    </div>

                    {sessions.length === 0 ? (
                        <div className="empty-state" style={{ padding: '2rem' }}>
                            No capture sessions recorded
                        </div>
                    ) : (
                        paginatedSessions.map((s, i) => (
                            <div key={s.id}>
                                <div
                                    style={{
                                        display: 'grid',
                                        gridTemplateColumns: '60px 1fr 140px 90px 90px 70px 70px 140px',
                                        padding: '0.7rem 1.25rem',
                                        borderBottom: '1px solid rgba(255,255,255,0.04)',
                                        fontSize: '0.82rem',
                                        cursor: 'pointer',
                                        background: expandedSession === s.id ? 'rgba(139,92,246,0.04)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                                        transition: 'background 0.15s',
                                        alignItems: 'center',
                                    }}
                                    onClick={() => setExpandedSession(prev => prev === s.id ? null : s.id)}
                                >
                                    <span className="td-muted" style={{ fontSize: '0.75rem' }}>
                                        {expandedSession === s.id ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                                        &nbsp;#{s.id}
                                    </span>
                                    <span style={{ color: '#c0c0c0', fontSize: '0.78rem' }}>{fmtTime(s.start_time)}</span>
                                    <span className="badge-proto" style={{
                                        background: 'rgba(59,130,246,0.08)', color: '#3b82f6',
                                        border: '1px solid rgba(59,130,246,0.18)',
                                        justifySelf: 'start',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                        maxWidth: '130px', display: 'inline-block',
                                    }}>{s.interface}</span>
                                    <span className="td-muted">{(s.packets || 0).toLocaleString()}</span>
                                    <span className="td-muted">{s.bytes_display}</span>
                                    <span className="mono" style={{
                                        color: s.alerts > 0 ? '#ff6b9d' : '#484f58',
                                        fontWeight: s.alerts > 0 ? 600 : 400,
                                    }}>{s.alerts}</span>
                                    <span className="td-muted">{s.connections}</span>
                                    <div className="flex-row gap-sm" style={{ position: 'relative' }}>
                                        <button
                                            onClick={e => {
                                                e.stopPropagation()
                                                setMenuOpen(menuOpen === s.id ? null : s.id)
                                            }}
                                            className="btn-blue-sm"
                                            style={{
                                                padding: '6px',
                                                background: menuOpen === s.id ? 'rgba(255,255,255,0.1)' : 'transparent',
                                                borderColor: 'transparent',
                                                color: '#7d8590'
                                            }}
                                        >
                                            <MoreHorizontal size={16} />
                                        </button>

                                        {menuOpen === s.id && (
                                            <div
                                                className="action-menu fade-in"
                                                style={{
                                                    position: 'absolute',
                                                    top: '100%',
                                                    right: 'auto',
                                                    left: 0,
                                                    marginTop: '4px',
                                                    zIndex: 50,
                                                    background: '#1e2430',
                                                    border: '1px solid rgba(255,255,255,0.1)',
                                                    borderRadius: '10px',
                                                    boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
                                                    padding: '6px',
                                                    display: 'flex',
                                                    flexDirection: 'column',
                                                    gap: '4px',
                                                    minWidth: '130px',
                                                    cursor: 'default'
                                                }}
                                                onClick={e => e.stopPropagation()}
                                            >
                                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0 4px 4px 4px', borderBottom: '1px solid rgba(255,255,255,0.05)', marginBottom: '2px' }}>
                                                    <span style={{ fontSize: '0.7rem', fontWeight: 600, color: '#7d8590', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Actions</span>
                                                    <button onClick={e => { e.stopPropagation(); setMenuOpen(null) }} style={{ background: 'transparent', border: 'none', color: '#7d8590', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center', justifyContent: 'center', borderRadius: '4px' }}>
                                                        <X size={14} />
                                                    </button>
                                                </div>

                                                {sessionId === s.id ? (
                                                    <button onClick={e => { e.stopPropagation(); unloadSession(); setMenuOpen(null) }}
                                                        className="btn-violet" style={{ padding: '6px 10px', fontSize: '0.75rem', justifyContent: 'flex-start' }}>
                                                        <Square size={12} /> Unload
                                                    </button>
                                                ) : (
                                                    <button onClick={e => { e.stopPropagation(); loadSession(s.id); setMenuOpen(null) }}
                                                        className="btn-blue-sm" style={{
                                                            padding: '6px 10px', fontSize: '0.75rem', justifyContent: 'flex-start',
                                                            background: 'rgba(34,197,94,0.06)', borderColor: 'rgba(34,197,94,0.15)',
                                                            color: '#22c55e',
                                                        }}>
                                                        <Play size={12} /> Load
                                                    </button>
                                                )}

                                                {s.end_time && (
                                                    <button onClick={e => {
                                                        e.stopPropagation()
                                                        window.open(`http://localhost:8000/api/connections/export/csv?session_id=${s.id}`, '_blank')
                                                        setMenuOpen(null)
                                                    }}
                                                        className="btn-blue-sm" style={{
                                                            padding: '6px 10px', fontSize: '0.75rem', justifyContent: 'flex-start',
                                                            background: 'rgba(0,200,255,0.06)', borderColor: 'rgba(0,200,255,0.15)',
                                                            color: '#44ccdd',
                                                        }}>
                                                        <Download size={12} /> Export CSV
                                                    </button>
                                                )}

                                                <button
                                                    onClick={e => requestDeleteSession(s.id, e)}
                                                    disabled={deletingSession === s.id || sessionId === s.id}
                                                    title={sessionId === s.id ? 'Unload this session before deleting' : 'Delete session'}
                                                    className="btn-danger" style={{
                                                        padding: '6px 10px', fontSize: '0.75rem', justifyContent: 'flex-start',
                                                        background: sessionId === s.id ? 'rgba(255,255,255,0.02)' : undefined,
                                                        borderColor: sessionId === s.id ? 'rgba(255,255,255,0.05)' : undefined,
                                                        color: sessionId === s.id ? '#484f58' : undefined,
                                                        cursor: sessionId === s.id ? 'not-allowed' : undefined,
                                                        opacity: (deletingSession === s.id || sessionId === s.id) ? 0.5 : 1,
                                                    }}>
                                                    <Trash2 size={12} />
                                                    {deletingSession === s.id ? 'Deleting…' : 'Delete'}
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Expanded detail */}
                                {expandedSession === s.id && (
                                    <div className="detail-row" style={{
                                        padding: '0.85rem 1.25rem 1rem 2.5rem',
                                        background: 'rgba(139,92,246,0.03)',
                                    }}>
                                        <div className="detail-grid">
                                            {[
                                                ['Session ID', `#${s.id}`],
                                                ['Interface', s.interface],
                                                ['Status', s.status],
                                                ['Started', fmtTime(s.start_time)],
                                                ['Ended', fmtTime(s.end_time)],
                                                ['Packets', (s.packets || 0).toLocaleString()],
                                                ['Data', s.bytes_display],
                                                ['Alerts', s.alerts.toString()],
                                                ['Connections', s.connections.toString()],
                                                ['Pcap File', s.pcap_file || '—'],
                                                ['Pcap Size', s.pcap_size || '—'],
                                                ['Pcap Exists', s.pcap_exists ? '✓ Yes' : '✕ No'],
                                            ].map(([label, val]) => (
                                                <div key={label} className="detail-item">
                                                    <div className="detail-item-label" style={{ fontWeight: 600 }}>{label}</div>
                                                    <div className="detail-item-value" style={{
                                                        fontFamily: typeof val === 'string' && (val.includes('.') || val.includes('_')) ? 'monospace' : 'inherit',
                                                        wordBreak: 'break-all',
                                                    }}>{val}</div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))
                    )}
                </div>

                {/* ── Session Pagination Bar ── */}
                {sessions.length > sessPerPage && (
                    <div className="pagination-bar" style={{ borderTop: '1px solid rgba(255,255,255,0.04)', padding: '0.65rem 1.25rem' }}>
                        <span>
                            Showing <span className="text-white">{sessRangeStart.toLocaleString()}–{sessRangeEnd.toLocaleString()}</span> of{' '}
                            <span className="text-white">{sessions.length.toLocaleString()}</span> sessions
                        </span>

                        <div className="pagination-controls">
                            <button onClick={() => setSessPage(1)} disabled={sessPage === 1} className="page-btn">
                                <ChevronsLeft size={14} />
                            </button>
                            <button onClick={() => setSessPage(p => Math.max(1, p - 1))} disabled={sessPage === 1} className="page-btn">
                                <ChevronLeft size={14} />
                            </button>

                            {(() => {
                                const pages = []
                                let start = Math.max(1, sessPage - 2)
                                let end = Math.min(sessTotalPages, start + 4)
                                if (end - start < 4) start = Math.max(1, end - 4)
                                for (let i = start; i <= end; i++) pages.push(i)
                                return pages.map(p => (
                                    <button key={p} onClick={() => setSessPage(p)}
                                        className={`page-btn${p === sessPage ? ' active' : ''}`}>
                                        {p}
                                    </button>
                                ))
                            })()}

                            <button onClick={() => setSessPage(p => Math.min(sessTotalPages, p + 1))} disabled={sessPage === sessTotalPages} className="page-btn">
                                <ChevronRight size={14} />
                            </button>
                            <button onClick={() => setSessPage(sessTotalPages)} disabled={sessPage === sessTotalPages} className="page-btn">
                                <ChevronsRight size={14} />
                            </button>

                            <span className="pagination-info">
                                Page {sessPage} of {sessTotalPages.toLocaleString()}
                            </span>
                        </div>
                    </div>
                )}
            </div>

            {/* ── About Panel ── */}
            <div className="panel">
                <div className="panel-header">
                    <span className="panel-title">
                        <Info size={16} style={{ color: '#3b82f6' }} />
                        About FlowSentrix
                    </span>
                </div>
                <div className="detail-grid" style={{ color: '#7d8590', fontSize: '0.85rem' }}>
                    {[
                        ['Version', '1.0.0', true],
                        ['Engine', 'TShark + Dumpcap + Suricata', false],
                        ['Architecture', 'Zero-drop capture with behavioral analysis', false],
                        ['Database', data?.db_path || 'data/flowsentrix.db', false],
                    ].map(([label, val, bold]) => (
                        <div key={label}>
                            <div className="detail-item-label" style={{ fontWeight: 600, marginBottom: '4px' }}>{label}</div>
                            <div style={{
                                fontWeight: bold ? 600 : 400,
                                color: bold ? '#e6edf3' : 'inherit',
                                fontFamily: label === 'Database' ? 'monospace' : 'inherit',
                                fontSize: label === 'Database' ? '0.78rem' : 'inherit',
                            }}>{val}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* ── Confirmation Modal (portal to body) ── */}
            {confirmModal && createPortal(
                <div style={{
                    position: 'fixed', inset: 0, zIndex: 1000,
                    background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(6px)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    animation: 'fadeIn 0.15s ease',
                }} onClick={() => setConfirmModal(null)}>
                    <div style={{
                        width: '420px', maxWidth: '90vw',
                        background: '#161b22', border: '1px solid rgba(239,68,68,0.2)',
                        borderRadius: '16px', padding: '1.75rem',
                        boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
                        animation: 'fadeIn 0.2s ease',
                    }} onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
                            <div style={{
                                width: '42px', height: '42px', borderRadius: '12px', flexShrink: 0,
                                background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                            }}>
                                <AlertTriangle size={20} color="#ef4444" />
                            </div>
                            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#e6edf3' }}>{confirmModal.title}</h3>
                        </div>
                        <p style={{ fontSize: '0.9rem', color: '#7d8590', lineHeight: 1.6, marginBottom: '1.5rem' }}>
                            {confirmModal.message}
                        </p>
                        <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
                            <button
                                onClick={() => setConfirmModal(null)}
                                className="btn-primary"
                                style={{
                                    background: 'rgba(255,255,255,0.06)', borderColor: 'rgba(255,255,255,0.1)',
                                    color: '#c0c0c0', padding: '0.55rem 1.2rem', fontSize: '0.85rem',
                                }}
                            >
                                Cancel
                            </button>
                            <button
                                onClick={confirmModal.onConfirm}
                                className="btn-danger"
                                style={{
                                    padding: '0.55rem 1.2rem', fontSize: '0.85rem', fontWeight: 700,
                                    background: 'rgba(239,68,68,0.15)', borderColor: 'rgba(239,68,68,0.35)',
                                }}
                            >
                                <Trash2 size={14} />
                                {confirmModal.confirmLabel}
                            </button>
                        </div>
                    </div>
                </div>
                , document.body)}
        </>
    )
}

export default Settings
