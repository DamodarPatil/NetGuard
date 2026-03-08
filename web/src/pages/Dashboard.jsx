import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Activity, Wifi, HardDrive, Cpu, ArrowUpRight, AlertTriangle } from 'lucide-react'
import { Sparkline, PieChart } from '../components/Charts'
import { useSession } from '../context/SessionContext'
import { useApiCache } from '../hooks/useApiCache'

const API = 'http://localhost:8000'

const Dashboard = () => {
    const [apiOnline, setApiOnline] = useState(true)
    const { sessionId } = useSession()
    const navigate = useNavigate()

    // SWR cache — shows last-known data instantly, refreshes in background
    const { data: stats } = useApiCache(
        `dashboard-stats-${sessionId || 0}`,
        async () => {
            const sessionParam = sessionId ? `?session_id=${sessionId}` : ''
            const res = await fetch(`${API}/api/stats${sessionParam}`)
            setApiOnline(true)
            return res.json()
        },
        { deps: [sessionId], fallback: null }
    )

    const { data: alertsData } = useApiCache(
        `dashboard-alerts-${sessionId || 0}`,
        async () => {
            const res = await fetch(`${API}/api/alerts?per_page=10${sessionId ? `&session_id=${sessionId}` : ''}`)
            return res.json()
        },
        { deps: [sessionId], fallback: { alerts: [] } }
    )

    const { data: timeseries } = useApiCache(
        `dashboard-timeseries-${sessionId || 0}`,
        async () => {
            const res = await fetch(`${API}/api/stats/timeseries${sessionId ? `?session_id=${sessionId}` : ''}`)
            return res.json()
        },
        { deps: [sessionId], fallback: { packets: [0], bytes: [0], sessions: [0] } }
    )

    // Also poll on an interval for freshness
    useEffect(() => {
        const fetchData = async () => {
            try {
                const sessionParam = sessionId ? `?session_id=${sessionId}` : ''
                await fetch(`${API}/api/stats${sessionParam}`)
                setApiOnline(true)
            } catch { setApiOnline(false) }
        }
        const interval = setInterval(fetchData, 5000)
        return () => clearInterval(interval)
    }, [sessionId])

    const alerts = (alertsData?.alerts || []).map(a => ({
        id: a.id,
        title: a.signature || a.title || 'Unknown Alert',
        meta: a.meta || `${a.src_ip} → ${a.dst_ip}`,
        severity: a.severity,
        timestamp: a.timestamp,
    }))

    // Sparkline data from the real timeseries endpoint
    const sparkPackets = timeseries?.packets?.length > 1 ? timeseries.packets : [0, 0]
    const sparkBytes = timeseries?.bytes?.length > 1 ? timeseries.bytes : [0, 0]
    const sparkSessions = timeseries?.sessions?.length > 1 ? timeseries.sessions : [0, 0]

    const pktVal = stats?.total_packets?.value || '0'
    const pktUnit = stats?.total_packets?.unit || ''
    const bytesVal = stats?.total_bytes?.value || '0'
    const bytesUnit = stats?.total_bytes?.unit || 'B'
    const sessions = stats?.session_count || 0
    const connections = stats?.connection_count || 0
    const protocols = stats?.protocols || []

    const fmtPkt = (n) => {
        if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
        if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
        return String(n || 0)
    }

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">Dashboard</h1>
                    <p className="page-subtitle">System overview and monitoring status</p>
                </div>
                <div className="status-badge">
                    <Wifi size={16} className="icon" />
                    <span>{apiOnline ? 'Engine Online' : 'Engine Offline'}</span>
                    <div className={`status-dot ${apiOnline ? 'online' : ''}`}></div>
                </div>
            </div>

            {/* Stat Cards */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-card-top">
                        <span className="stat-label">Total Packets</span>
                        <div className="stat-icon cyan"><Activity size={20} /></div>
                    </div>
                    <div className="stat-value">{pktVal}{pktUnit && <span className="stat-unit">{pktUnit}</span>}</div>
                    <div className="stat-trend"><ArrowUpRight size={14} /> {connections.toLocaleString()} connections</div>
                    <Sparkline data={sparkPackets} color="#3b82f6" />
                </div>

                <div className="stat-card">
                    <div className="stat-card-top">
                        <span className="stat-label">Capture Sessions</span>
                        <div className="stat-icon purple"><Cpu size={20} /></div>
                    </div>
                    <div className="stat-value">{sessions}</div>
                    <div className="stat-trend"><ArrowUpRight size={14} /> {connections.toLocaleString()} total flows</div>
                    <Sparkline data={sparkSessions} color="#8b5cf6" />
                </div>

                <div className="stat-card">
                    <div className="stat-card-top">
                        <span className="stat-label">Data Processed</span>
                        <div className="stat-icon green"><HardDrive size={20} /></div>
                    </div>
                    <div className="stat-value">{bytesVal}<span className="stat-unit">{bytesUnit}</span></div>
                    <div className="stat-trend"><ArrowUpRight size={14} /> Across all sessions</div>
                    <Sparkline data={sparkBytes} color="#22c55e" />
                </div>
            </div>

            {/* Protocol Distribution */}
            {protocols.length > 0 && (
                <div className="panel">
                    <div className="panel-header">
                        <span className="panel-title">
                            <Activity size={16} style={{ color: '#3b82f6' }} />
                            Protocol Distribution
                        </span>
                        <span className="alert-count-badge">{protocols.length} protocols</span>
                    </div>
                    <div className="proto-panel-body">
                        <PieChart
                            protocols={protocols}
                            centerLabel={pktVal}
                            centerSub={`${pktUnit} PKTS`}
                        />
                        <div className="proto-legend">
                            {protocols.map((p, i) => (
                                <div className="legend-row" key={i}>
                                    <div className="legend-info">
                                        <div className="legend-dot" style={{ background: p.color }} />
                                        <span className="legend-name">{p.name}</span>
                                    </div>
                                    <div className="legend-bar-track">
                                        <div className="legend-bar-fill" style={{
                                            width: `${Math.max(p.pct, 2)}%`,
                                            background: `linear-gradient(90deg, ${p.color}40, ${p.color})`,
                                            boxShadow: `0 0 6px ${p.color}30`,
                                        }} />
                                    </div>
                                    <div className="legend-stats">
                                        <span className="legend-pkt">{fmtPkt(p.packets)}</span>
                                        <span className="legend-pct">{p.pct}%</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {/* Recent Alerts */}
            <div className="panel">
                <div className="panel-header">
                    <span className="panel-title">
                        <AlertTriangle size={16} className="icon" />
                        Recent Alerts
                    </span>
                    <span className="alert-count-badge">{alerts.length} total</span>
                </div>
                <div className="alert-list">
                    {alerts.length === 0 && (
                        <div style={{ color: '#484f58', fontSize: '0.85rem', padding: '1rem', textAlign: 'center' }}>
                            No alerts recorded yet
                        </div>
                    )}
                    {alerts.map((alert, i) => {
                        const sevLabel = { high: 'CRITICAL', medium: 'WARNING', low: 'INFO' }[alert.severity] || 'INFO'
                        return (
                            <div
                                className={`alert-row ${alert.severity}`}
                                key={i}
                                style={{ cursor: 'pointer' }}
                                onClick={() => navigate(`/alerts?alert_id=${alert.id}`)}
                            >
                                <AlertTriangle size={18} className="alert-icon" />
                                <div className="alert-info">
                                    <div className="alert-title">{alert.title}</div>
                                    <div className="alert-meta">{alert.meta}</div>
                                </div>
                                <span className={`severity-badge ${alert.severity}`}>
                                    {sevLabel}
                                </span>
                                <span className="alert-time">{alert.timestamp}</span>
                            </div>
                        )
                    })}
                </div>
            </div>
        </>
    )
}

export default Dashboard
