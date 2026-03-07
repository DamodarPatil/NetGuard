import { useState, useEffect, useCallback } from 'react'
import {
    Settings as SettingsIcon, CheckCircle, XCircle, Shield, HardDrive,
    Database, Trash2, RefreshCw, Monitor, Cpu, AlertTriangle,
    FileText, Clock, Activity, ChevronDown, ChevronRight, Info,
    Play, Square, Download
} from 'lucide-react'
import { useSession } from '../context/SessionContext'
import { useApiCache } from '../hooks/useApiCache'

const API = 'http://localhost:8000'

// ── Status pill component ──
const StatusPill = ({ ok, label }) => (
    <div style={{
        display: 'inline-flex', alignItems: 'center', gap: '6px',
        padding: '4px 12px', borderRadius: '20px',
        background: ok ? 'rgba(0,255,115,0.08)' : 'rgba(255,42,42,0.08)',
        border: `1px solid ${ok ? 'rgba(0,255,115,0.2)' : 'rgba(255,42,42,0.2)'}`,
        fontSize: '0.72rem', fontWeight: 600,
        color: ok ? '#00ff73' : '#ff2a2a',
    }}>
        {ok ? <CheckCircle size={12} /> : <XCircle size={12} />}
        {label || (ok ? 'Available' : 'Not Found')}
    </div>
)

// ── Dependency row ──
const DepRow = ({ name, icon, installed, version, extra }) => (
    <div style={{
        display: 'flex', alignItems: 'center', gap: '1rem',
        padding: '0.85rem 1.25rem',
        borderBottom: '1px solid rgba(255,255,255,0.04)',
        transition: 'background 0.15s',
    }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
    >
        <div style={{
            width: '36px', height: '36px', borderRadius: '10px', flexShrink: 0,
            background: installed ? 'rgba(0,255,115,0.08)' : 'rgba(255,42,42,0.06)',
            border: `1px solid ${installed ? 'rgba(0,255,115,0.15)' : 'rgba(255,42,42,0.15)'}`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: installed ? '#00ff73' : '#ff2a2a',
        }}>
            {icon}
        </div>
        <div style={{ flex: 1 }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#e0e0e0' }}>{name}</div>
            {version && <div style={{ fontSize: '0.72rem', color: '#5a5a6e', fontFamily: 'monospace' }}>{version}</div>}
            {extra && <div style={{ fontSize: '0.72rem', color: '#5a5a6e' }}>{extra}</div>}
        </div>
        <StatusPill ok={installed} />
    </div>
)

// ── Data stat box ──
const DataBox = ({ label, value, sub, color, icon }) => (
    <div style={{
        flex: 1, minWidth: '140px',
        padding: '1.25rem 1.5rem', borderRadius: '14px',
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(12px)',
    }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem' }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: '#5a5a6e', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</span>
            <div style={{
                width: '32px', height: '32px', borderRadius: '8px',
                background: `${color}12`, border: `1px solid ${color}20`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color,
            }}>{icon}</div>
        </div>
        <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fff', lineHeight: 1 }}>{value}</div>
        {sub && <div style={{ fontSize: '0.72rem', color: '#5a5a6e', marginTop: '0.4rem' }}>{sub}</div>}
    </div>
)

// ═══════════════════════════════════════════════════════════════
// Settings Page
// ═══════════════════════════════════════════════════════════════
const Settings = () => {
    const [clearing, setClearing] = useState(false)
    const [deletingSession, setDeletingSession] = useState(null)
    const [confirmClear, setConfirmClear] = useState(false)
    const [expandedSession, setExpandedSession] = useState(null)
    const { sessionId, loadSession, unloadSession } = useSession()

    // SWR cache — shows last-known data instantly, refreshes in background
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
        try {
            const res = await fetch(`${API}/api/settings/clear`, { method: 'POST' })
            const result = await res.json()
            if (result.ok) {
                setConfirmClear(false)
                fetchData()
            }
        } catch (e) { /* */ }
        finally { setClearing(false) }
    }

    const handleDeleteSession = async (sessionId) => {
        setDeletingSession(sessionId)
        try {
            const res = await fetch(`${API}/api/settings/sessions/${sessionId}`, { method: 'DELETE' })
            const result = await res.json()
            if (result.ok) {
                fetchData()
            }
        } catch (e) { /* */ }
        finally { setDeletingSession(null) }
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
                <div className="panel" style={{ textAlign: 'center', padding: '3rem', color: '#5a5a6e' }}>
                    <SettingsIcon size={32} style={{ marginBottom: '0.75rem', opacity: 0.3 }} />
                    <p>Loading system information…</p>
                </div>
            </>
        )
    }

    const sessions = data?.sessions || []

    return (
        <>
            {/* ── Page Header ── */}
            <div className="page-header">
                <div>
                    <h1 className="page-title">Settings</h1>
                    <p className="page-subtitle">System status and data management</p>
                </div>
                <button
                    onClick={fetchData}
                    style={{
                        display: 'flex', alignItems: 'center', gap: '0.4rem',
                        padding: '0.45rem 0.9rem', borderRadius: '8px',
                        background: 'rgba(188,19,254,0.1)', border: '1px solid rgba(188,19,254,0.2)',
                        color: '#bc13fe', cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600,
                    }}
                >
                    <RefreshCw size={13} />
                    Refresh
                </button>
            </div>

            {/* ── System Status Panel ── */}
            {system && (
                <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                    <div className="panel-header" style={{ padding: '1rem 1.25rem', marginBottom: 0 }}>
                        <span className="panel-title">
                            <Monitor size={16} style={{ color: '#00ff73' }} />
                            System Dependencies
                        </span>
                        <StatusPill ok={system.root} label={system.root ? 'Root Access' : 'No Root'} />
                    </div>

                    <DepRow
                        name="TShark (Wireshark Engine)"
                        icon={<Activity size={16} />}
                        installed={system.tshark.installed}
                        version={system.tshark.version ? `v${system.tshark.version}` : ''}
                        extra="Packet analysis and protocol dissection"
                    />
                    <DepRow
                        name="Dumpcap"
                        icon={<HardDrive size={16} />}
                        installed={system.dumpcap.installed}
                        version={system.dumpcap.version ? `v${system.dumpcap.version}` : ''}
                        extra="Zero-drop packet capture engine"
                    />
                    <DepRow
                        name="Suricata IDS"
                        icon={<Shield size={16} />}
                        installed={system.suricata.installed}
                        version={system.suricata.version || ''}
                        extra="Signature-based intrusion detection"
                    />
                    <DepRow
                        name="Suricata Rules"
                        icon={<FileText size={16} />}
                        installed={system.suricata_rules.loaded}
                        version={system.suricata_rules.loaded ? `${system.suricata_rules.count.toLocaleString()} active rules` : ''}
                        extra={system.suricata_rules.loaded ? '/var/lib/suricata/rules/suricata.rules' : 'Run: sudo suricata-update'}
                    />

                    {/* System info footer */}
                    <div style={{
                        display: 'flex', gap: '2rem', padding: '0.75rem 1.25rem',
                        borderTop: '1px solid rgba(255,255,255,0.04)',
                        fontSize: '0.72rem', color: '#3d3d4e', flexWrap: 'wrap',
                    }}>
                        <span>Python {system.python_version}</span>
                        <span>{system.os}</span>
                        <span>{system.machine}</span>
                    </div>
                </div>
            )}

            {/* ── Data Overview Cards ── */}
            {data && (
                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                    <DataBox
                        label="Database" value={data.db_size_display}
                        sub={sessions.length + ' sessions'} color="#bc13fe"
                        icon={<Database size={16} />}
                    />
                    <DataBox
                        label="Capture Files" value={data.pcap_total_display}
                        sub={data.pcap_count + ' pcapng files'} color="#00f3ff"
                        icon={<HardDrive size={16} />}
                    />
                    <DataBox
                        label="Total Sessions" value={sessions.length}
                        sub="Capture histories" color="#00ff73"
                        icon={<Cpu size={16} />}
                    />
                </div>
            )}

            {/* ── Data Management Panel ── */}
            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
                <div className="panel-header" style={{ padding: '1rem 1.25rem', marginBottom: 0 }}>
                    <span className="panel-title">
                        <Database size={16} style={{ color: '#bc13fe' }} />
                        Data Management
                    </span>
                </div>

                <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                        {/* Danger zone: Clear all */}
                        {!confirmClear ? (
                            <button
                                onClick={() => setConfirmClear(true)}
                                style={{
                                    display: 'flex', alignItems: 'center', gap: '0.4rem',
                                    padding: '0.55rem 1.1rem', borderRadius: '8px',
                                    background: 'rgba(255,42,42,0.08)',
                                    border: '1px solid rgba(255,42,42,0.2)',
                                    color: '#ff2a2a', cursor: 'pointer',
                                    fontSize: '0.8rem', fontWeight: 600,
                                    transition: 'all 0.15s',
                                }}
                            >
                                <Trash2 size={14} />
                                Clear All Sessions
                            </button>
                        ) : (
                            <div style={{
                                display: 'flex', alignItems: 'center', gap: '0.6rem',
                                padding: '0.6rem 1rem', borderRadius: '10px',
                                background: 'rgba(255,42,42,0.06)',
                                border: '1px solid rgba(255,42,42,0.2)',
                            }}>
                                <AlertTriangle size={16} color="#ff2a2a" />
                                <span style={{ fontSize: '0.82rem', color: '#ff6b9d', fontWeight: 500 }}>
                                    Delete all sessions, connections & alerts?
                                </span>
                                <button
                                    onClick={handleClearAll}
                                    disabled={clearing}
                                    style={{
                                        padding: '0.4rem 0.85rem', borderRadius: '6px',
                                        background: 'rgba(255,42,42,0.2)', border: '1px solid rgba(255,42,42,0.4)',
                                        color: '#ff2a2a', cursor: 'pointer', fontSize: '0.78rem', fontWeight: 700,
                                    }}
                                >
                                    {clearing ? 'Clearing…' : 'Yes, Delete All'}
                                </button>
                                <button
                                    onClick={() => setConfirmClear(false)}
                                    style={{
                                        padding: '0.4rem 0.85rem', borderRadius: '6px',
                                        background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
                                        color: '#5a5a6e', cursor: 'pointer', fontSize: '0.78rem', fontWeight: 600,
                                    }}
                                >
                                    Cancel
                                </button>
                            </div>
                        )}

                        <div style={{ flex: 1 }} />

                        {data && (
                            <span style={{ fontSize: '0.72rem', color: '#3d3d4e' }}>
                                DB: {data.db_size_display} &nbsp;·&nbsp; Captures: {data.pcap_total_display}
                            </span>
                        )}
                    </div>
                </div>

                {/* ── Session History Table ── */}
                <div style={{ padding: '0 0 0 0' }}>
                    {/* Table header */}
                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: '60px 1fr 140px 90px 90px 70px 70px 140px',
                        padding: '0.65rem 1.25rem',
                        borderBottom: '1px solid rgba(255,255,255,0.06)',
                        fontSize: '0.68rem', fontWeight: 600, color: '#3d3d4e',
                        textTransform: 'uppercase', letterSpacing: '0.08em',
                    }}>
                        <span>ID</span>
                        <span>Started</span>
                        <span>Interface</span>
                        <span>Packets</span>
                        <span>Data</span>
                        <span>Alerts</span>
                        <span>Flows</span>
                        <span>Actions</span>
                    </div>

                    {sessions.length === 0 ? (
                        <div style={{ padding: '2rem', textAlign: 'center', color: '#3d3d4e', fontSize: '0.85rem' }}>
                            No capture sessions recorded
                        </div>
                    ) : (
                        sessions.map((s, i) => (
                            <div key={s.id}>
                                <div
                                    style={{
                                        display: 'grid',
                                        gridTemplateColumns: '60px 1fr 140px 90px 90px 70px 70px 140px',
                                        padding: '0.7rem 1.25rem',
                                        borderBottom: '1px solid rgba(255,255,255,0.04)',
                                        fontSize: '0.82rem',
                                        cursor: 'pointer',
                                        background: expandedSession === s.id ? 'rgba(188,19,254,0.04)' : i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)',
                                        transition: 'background 0.15s',
                                        alignItems: 'center',
                                    }}
                                    onClick={() => setExpandedSession(prev => prev === s.id ? null : s.id)}
                                    onMouseEnter={e => { if (expandedSession !== s.id) e.currentTarget.style.background = 'rgba(255,255,255,0.03)' }}
                                    onMouseLeave={e => { if (expandedSession !== s.id) e.currentTarget.style.background = i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}
                                >
                                    <span style={{ color: '#5a5a6e', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                        {expandedSession === s.id ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                                        &nbsp;#{s.id}
                                    </span>
                                    <span style={{ color: '#c0c0c0', fontSize: '0.78rem' }}>{fmtTime(s.start_time)}</span>
                                    <span style={{
                                        fontSize: '0.7rem', fontWeight: 600, padding: '2px 8px', borderRadius: '4px',
                                        background: 'rgba(0,243,255,0.08)', color: '#00f3ff',
                                        border: '1px solid rgba(0,243,255,0.18)',
                                        fontFamily: 'monospace', justifySelf: 'start',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                        maxWidth: '130px', display: 'inline-block',
                                    }}>{s.interface}</span>
                                    <span style={{ color: '#8b8b9b', fontFamily: 'monospace' }}>{(s.packets || 0).toLocaleString()}</span>
                                    <span style={{ color: '#8b8b9b', fontFamily: 'monospace' }}>{s.bytes_display}</span>
                                    <span style={{
                                        color: s.alerts > 0 ? '#ff6b9d' : '#3d3d4e',
                                        fontWeight: s.alerts > 0 ? 600 : 400,
                                        fontFamily: 'monospace',
                                    }}>{s.alerts}</span>
                                    <span style={{ color: '#8b8b9b', fontFamily: 'monospace' }}>{s.connections}</span>
                                    <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
                                        {/* Load / Unload button */}
                                        {sessionId === s.id ? (
                                            <button
                                                onClick={e => { e.stopPropagation(); unloadSession() }}
                                                style={{
                                                    display: 'flex', alignItems: 'center', gap: '4px',
                                                    padding: '4px 10px', borderRadius: '6px',
                                                    background: 'rgba(188,19,254,0.12)', border: '1px solid rgba(188,19,254,0.3)',
                                                    color: '#bc13fe', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 600,
                                                    transition: 'all 0.15s',
                                                }}
                                            >
                                                <Square size={10} />
                                                Unload
                                            </button>
                                        ) : (
                                            <button
                                                onClick={e => { e.stopPropagation(); loadSession(s.id) }}
                                                style={{
                                                    display: 'flex', alignItems: 'center', gap: '4px',
                                                    padding: '4px 10px', borderRadius: '6px',
                                                    background: 'rgba(0,255,115,0.06)', border: '1px solid rgba(0,255,115,0.15)',
                                                    color: '#00ff73', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 600,
                                                    transition: 'all 0.15s',
                                                }}
                                            >
                                                <Play size={10} />
                                                Load
                                            </button>
                                        )}

                                        {/* Export CSV — only for completed sessions */}
                                        {s.end_time && (
                                            <button
                                                onClick={e => {
                                                    e.stopPropagation()
                                                    window.open(`http://localhost:8000/api/connections/export/csv?session_id=${s.id}`, '_blank')
                                                }}
                                                style={{
                                                    display: 'flex', alignItems: 'center', gap: '4px',
                                                    padding: '4px 10px', borderRadius: '6px',
                                                    background: 'rgba(0,200,255,0.06)', border: '1px solid rgba(0,200,255,0.15)',
                                                    color: '#44ccdd', cursor: 'pointer', fontSize: '0.7rem', fontWeight: 600,
                                                    transition: 'all 0.15s',
                                                }}
                                            >
                                                <Download size={10} />
                                                CSV
                                            </button>
                                        )}

                                        {/* Delete button — disabled when this session is loaded */}
                                        <button
                                            onClick={e => { e.stopPropagation(); handleDeleteSession(s.id) }}
                                            disabled={deletingSession === s.id || sessionId === s.id}
                                            title={sessionId === s.id ? 'Unload this session before deleting' : 'Delete session'}
                                            style={{
                                                display: 'flex', alignItems: 'center', gap: '4px',
                                                padding: '4px 10px', borderRadius: '6px',
                                                background: sessionId === s.id ? 'rgba(255,255,255,0.02)' : 'rgba(255,42,42,0.06)',
                                                border: `1px solid ${sessionId === s.id ? 'rgba(255,255,255,0.05)' : 'rgba(255,42,42,0.15)'}`,
                                                color: sessionId === s.id ? '#3d3d4e' : '#ff2a2a',
                                                cursor: sessionId === s.id ? 'not-allowed' : 'pointer',
                                                fontSize: '0.7rem', fontWeight: 600,
                                                opacity: (deletingSession === s.id || sessionId === s.id) ? 0.5 : 1,
                                                transition: 'all 0.15s',
                                            }}
                                        >
                                            <Trash2 size={11} />
                                            {deletingSession === s.id ? '…' : 'Delete'}
                                        </button>
                                    </div>
                                </div>

                                {/* Expanded detail */}
                                {expandedSession === s.id && (
                                    <div style={{
                                        padding: '0.85rem 1.25rem 1rem 2.5rem',
                                        borderBottom: '1px solid rgba(255,255,255,0.06)',
                                        background: 'rgba(188,19,254,0.03)',
                                    }}>
                                        <div style={{ display: 'flex', gap: '2.5rem', flexWrap: 'wrap' }}>
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
                                                <div key={label} style={{ minWidth: '110px' }}>
                                                    <div style={{
                                                        fontSize: '0.62rem', color: '#3d3d4e', marginBottom: '3px',
                                                        textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600,
                                                    }}>{label}</div>
                                                    <div style={{
                                                        fontSize: '0.8rem', color: '#c0c0c0',
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
            </div>

            {/* ── About Panel ── */}
            <div className="panel">
                <div className="panel-header">
                    <span className="panel-title">
                        <Info size={16} style={{ color: '#00f3ff' }} />
                        About NetGuard
                    </span>
                </div>
                <div style={{ display: 'flex', gap: '2.5rem', flexWrap: 'wrap', color: '#8b8b9b', fontSize: '0.85rem' }}>
                    <div>
                        <div style={{ fontSize: '0.62rem', color: '#3d3d4e', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '4px' }}>Version</div>
                        <div style={{ fontWeight: 600, color: '#e0e0e0' }}>1.0.0</div>
                    </div>
                    <div>
                        <div style={{ fontSize: '0.62rem', color: '#3d3d4e', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '4px' }}>Engine</div>
                        <div>TShark + Dumpcap + Suricata</div>
                    </div>
                    <div>
                        <div style={{ fontSize: '0.62rem', color: '#3d3d4e', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '4px' }}>Architecture</div>
                        <div>Zero-drop capture with behavioral analysis</div>
                    </div>
                    <div>
                        <div style={{ fontSize: '0.62rem', color: '#3d3d4e', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '4px' }}>Database</div>
                        <div style={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>{data?.db_path || 'data/netguard.db'}</div>
                    </div>
                </div>
            </div>
        </>
    )
}

export default Settings
