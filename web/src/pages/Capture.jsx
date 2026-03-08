import { useState, useEffect, useCallback, useRef } from 'react'
import { Radio, Play, Square, MonitorSpeaker, AlertTriangle, CheckCircle, Waves, Activity } from 'lucide-react'

const API = 'http://localhost:8000'

// Protocol colors matching CLI
const PROTO_COLORS = {
    'TLSv1.2': '#00f3ff', 'TLSv1.3': '#00f3ff', 'TLSv1': '#00b8cc',
    'TCP': '#bc13fe', 'UDP': '#ffaa00', 'QUIC': '#00ff73',
    'HTTP': '#ff9500', 'HTTP/JSON': '#ff9500', 'DNS': '#6ec6ff',
    'SSLv2': '#ff6b9d', 'SSL': '#ff6b9d', 'SSHv2': '#c5e1a5', 'SSH': '#c5e1a5',
    'ICMP': '#fff59d', 'ICMPv6': '#fff59d', 'ARP': '#ffcc80',
    'MDNS': '#80deea', 'NTP': '#b39ddb', 'DHCP': '#ef9a9a',
}

const StatBox = ({ label, value, sub, color = '#e0e0e0' }) => (
    <div className="stat-box">
        <div className="stat-box-label">{label}</div>
        <div className="stat-box-value" style={{ color }}>{value}</div>
        {sub && <div className="stat-box-sub">{sub}</div>}
    </div>
)

const Capture = () => {
    const [status, setStatus] = useState(null)
    const [interfaces, setInterfaces] = useState([])
    const [selectedIface, setSelectedIface] = useState('')
    const [actionError, setActionError] = useState('')
    const [actionLoading, setActionLoading] = useState(false)
    const [packets, setPackets] = useState([])
    const lastPacketId = useRef(0)
    const feedRef = useRef(null)
    const prevState = useRef(null)
    const isNearBottom = useRef(true)
    const pendingPackets = useRef([])

    const flushPending = useCallback(() => {
        if (pendingPackets.current.length === 0) return
        setPackets(prev => {
            const merged = [...prev, ...pendingPackets.current]
            pendingPackets.current = []
            return merged.length > 500 ? merged.slice(-500) : merged
        })
    }, [])

    useEffect(() => {
        fetch(`${API}/api/interfaces`)
            .then(r => r.json())
            .then(data => {
                setInterfaces(data.interfaces || [])
                const up = data.interfaces?.find(i => i.state === 'up' && i.name !== 'lo')
                if (up) setSelectedIface(up.name)
                else if (data.interfaces?.length) setSelectedIface(data.interfaces[0].name)
            })
            .catch(() => { })
    }, [])

    const fetchStatus = useCallback(async () => {
        try {
            const r = await fetch(`${API}/api/capture/status`)
            const data = await r.json()
            setStatus(data)
        } catch { }
    }, [])

    const fetchPackets = useCallback(async () => {
        try {
            const r = await fetch(`${API}/api/capture/packets?after_id=${lastPacketId.current}`)
            const data = await r.json()
            if (data.packets && data.packets.length > 0) {
                lastPacketId.current = data.packets[data.packets.length - 1].id
                if (isNearBottom.current) {
                    setPackets(prev => {
                        const merged = [...prev, ...data.packets]
                        return merged.length > 500 ? merged.slice(-500) : merged
                    })
                } else {
                    pendingPackets.current.push(...data.packets)
                    if (pendingPackets.current.length > 500) {
                        pendingPackets.current = pendingPackets.current.slice(-500)
                    }
                }
            }
        } catch { }
    }, [])

    useEffect(() => { fetchStatus() }, [fetchStatus])

    useEffect(() => {
        const wasActive = prevState.current === 'capturing' || prevState.current === 'stopping' || prevState.current === 'analyzing'
        const nowIdle = status?.state === 'idle'
        prevState.current = status?.state
        if (wasActive && nowIdle) {
            fetchPackets()
            setTimeout(fetchPackets, 500)
            setTimeout(fetchPackets, 1500)
        }
    }, [status?.state, fetchPackets])

    useEffect(() => {
        const isActive = status?.state === 'capturing' || status?.state === 'stopping' || status?.state === 'analyzing'
        const statusInterval = isActive ? 1000 : 3000
        const statusTimer = setInterval(fetchStatus, statusInterval)
        let packetTimer = null
        if (isActive) { packetTimer = setInterval(fetchPackets, 500) }
        return () => {
            clearInterval(statusTimer)
            if (packetTimer) clearInterval(packetTimer)
        }
    }, [fetchStatus, fetchPackets, status?.state])

    useEffect(() => {
        if (isNearBottom.current && feedRef.current) {
            feedRef.current.scrollTop = feedRef.current.scrollHeight
        }
    }, [packets])

    const handleScroll = () => {
        if (!feedRef.current) return
        const { scrollTop, scrollHeight, clientHeight } = feedRef.current
        const wasNearBottom = isNearBottom.current
        isNearBottom.current = (scrollHeight - scrollTop - clientHeight) < 40
        if (!wasNearBottom && isNearBottom.current) flushPending()
    }

    const handleStart = async () => {
        if (!selectedIface) { setActionError('Select an interface first'); return }
        setActionError('')
        setActionLoading(true)
        setPackets([])
        lastPacketId.current = 0
        isNearBottom.current = true
        try {
            const r = await fetch(`${API}/api/capture/start?interface=${encodeURIComponent(selectedIface)}`, { method: 'POST' })
            const data = await r.json()
            if (!data.ok) setActionError(data.error)
            fetchStatus()
        } catch (e) {
            setActionError('Failed to connect to API')
        } finally {
            setActionLoading(false)
        }
    }

    const handleStop = async () => {
        setActionError('')
        setActionLoading(true)
        try {
            const r = await fetch(`${API}/api/capture/stop`, { method: 'POST' })
            const data = await r.json()
            if (!data.ok) setActionError(data.error)
            fetchStatus()
        } catch (e) {
            setActionError('Failed to connect to API')
        } finally {
            setActionLoading(false)
        }
    }

    const isCapturing = status?.state === 'capturing'
    const isStopping = status?.state === 'stopping'
    const isAnalyzing = status?.state === 'analyzing'
    const isActive = isCapturing || isStopping || isAnalyzing
    const lastCap = status?.last_capture

    const stateConfig = {
        idle: { label: 'Idle', color: '#7d8590', bg: 'rgba(125,133,144,0.15)' },
        capturing: { label: '● LIVE', color: '#22c55e', bg: 'rgba(34,197,94,0.12)' },
        stopping: { label: '■ Stopping…', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
        analyzing: { label: '⟳ Analyzing…', color: '#3b82f6', bg: 'rgba(59,130,246,0.12)' },
    }
    const sc = stateConfig[status?.state] || stateConfig.idle
    const protoColor = (p) => PROTO_COLORS[p] || '#7d8590'

    const GRID = '60px 80px 75px 1fr 24px 1fr 60px 3.5fr'

    return (
        <>
            <div className="page-header">
                <div>
                    <h1 className="page-title">Capture</h1>
                    <p className="page-subtitle">
                        {isActive ? `Capturing on ${status.interface}` : 'Start and monitor live packet capture'}
                    </p>
                </div>
                <div className="capture-status" style={{
                    background: sc.bg, border: `1px solid ${sc.color}30`, color: sc.color,
                    ...(isCapturing ? { animation: 'glow-pulse 2s infinite' } : {}),
                }}>
                    {sc.label}
                </div>
            </div>

            {/* ── Controls Row ── */}
            <div className="capture-controls">
                <div className="panel flex-row gap-lg" style={{ flex: '0 0 auto', padding: '0.85rem 1.2rem' }}>
                    <select value={selectedIface} onChange={e => setSelectedIface(e.target.value)}
                        disabled={isActive} className="capture-select">
                        <option value="">Select interface…</option>
                        <option value="any">any (all interfaces)</option>
                        {interfaces.map(iface => (
                            <option key={iface.name} value={iface.name}>
                                {iface.name}{iface.ip ? ` (${iface.ip})` : ''}{iface.state === 'up' ? ' ● UP' : ''}
                            </option>
                        ))}
                    </select>

                    {!isActive ? (
                        <button onClick={handleStart} disabled={actionLoading || !selectedIface} className="btn-start">
                            <Play size={16} fill="#22c55e" />
                            Start
                        </button>
                    ) : (
                        <button onClick={handleStop} disabled={actionLoading || !isCapturing} className="btn-stop">
                            <Square size={14} fill={isCapturing ? '#ef4444' : '#7d8590'} />
                            {isStopping ? 'Stopping…' : isAnalyzing ? 'Analyzing…' : 'Stop'}
                        </button>
                    )}
                </div>

                {isActive && (
                    <div className="capture-live-stats">
                        <StatBox label="Packets" value={status.pcap_packets?.toLocaleString() || '0'} color="#3b82f6" />
                        <StatBox label="Data" value={status.pcap_bytes_display || '0 B'} color="#8b5cf6" />
                        <StatBox label="Duration" value={status.duration_display || '0s'} color="#f59e0b" />
                        <StatBox label="PPS" value={status.pps?.toLocaleString() || '0'} sub="pkts/sec" color="#22c55e" />
                    </div>
                )}
            </div>

            {/* Error */}
            {actionError && (
                <div className="error-banner">
                    <AlertTriangle size={16} />
                    {actionError}
                </div>
            )}

            {/* Analyzing */}
            {isAnalyzing && (
                <div className="panel analyzing-banner">
                    <Waves size={28} className="icon" style={{ animation: 'pulse 1.5s infinite' }} />
                    <p className="title">Analyzing capture data…</p>
                    <p className="subtitle">Reprocessing pcapng for accurate stats</p>
                </div>
            )}

            {/* ── Packet Feed ── */}
            {(isActive || packets.length > 0) && (
                <div className="panel" style={{ padding: 0, overflow: 'hidden', marginBottom: '0.75rem' }}>
                    <div className="panel-header">
                        <span className="panel-title">
                            <Activity size={16} style={{ color: '#3b82f6' }} />
                            Packet Feed
                            <span className="text-xs" style={{ color: '#484f58', marginLeft: '0.75rem' }}>
                                {packets.length} packets
                            </span>
                        </span>
                    </div>

                    {/* Column header */}
                    <div className="packet-feed-header" style={{ gridTemplateColumns: GRID }}>
                        <span>#</span><span>Time</span><span>Proto</span>
                        <span>Source</span><span></span><span>Destination</span>
                        <span style={{ textAlign: 'right', paddingRight: '1rem' }}>Len</span>
                        <span>Info</span>
                    </div>

                    {/* Scrollable feed */}
                    <div ref={feedRef} onScroll={handleScroll} className="packet-feed">
                        {packets.slice(-150).map((pkt, i) => {
                            const pc = protoColor(pkt.proto)
                            const isOut = pkt.direction === 'OUTGOING'
                            const isIn = pkt.direction === 'INCOMING'
                            return (
                                <div key={pkt.id} className="packet-row" style={{ gridTemplateColumns: GRID }}>
                                    <span className="text-muted">{pkt.num}</span>
                                    <span style={{ color: '#6e6e82' }}>{pkt.time.toFixed(3)}s</span>
                                    <span style={{ color: pc, fontWeight: 700 }}>{pkt.proto}</span>
                                    <span style={{
                                        color: isOut ? '#22c55e' : '#e6edf3',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>{pkt.src}</span>
                                    <span style={{
                                        color: isOut ? '#22c55e' : isIn ? '#6ec6ff' : '#484f58',
                                        fontWeight: 700, textAlign: 'center',
                                    }}>→</span>
                                    <span style={{
                                        color: isIn ? '#6ec6ff' : '#e6edf3',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>{pkt.dst}</span>
                                    <span style={{ color: '#6e6e82', textAlign: 'right', paddingRight: '1rem' }}>{pkt.length}</span>
                                    <span style={{
                                        color: '#7d8590', paddingLeft: '0.25rem',
                                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                    }}>{pkt.info}</span>
                                </div>
                            )
                        })}
                        {isCapturing && packets.length === 0 && (
                            <div className="waiting-text">Waiting for packets…</div>
                        )}
                    </div>
                </div>
            )}

            {/* ── Last Capture Summary ── */}
            {!isActive && lastCap && (
                <div className="panel">
                    <div className="panel-header">
                        <span className="panel-title">
                            <CheckCircle size={18} style={{ color: '#22c55e' }} />
                            Capture Complete
                        </span>
                    </div>
                    <div className="packet-summary">
                        <StatBox label="Packets" value={lastCap.packets?.toLocaleString() || '0'} color="#3b82f6" />
                        <StatBox label="Data" value={lastCap.bytes_display || '0 B'} color="#8b5cf6" />
                        <StatBox label="Duration" value={lastCap.duration_display || '—'} color="#f59e0b" />
                        <StatBox label="Session" value={`#${lastCap.session_id || '—'}`} color="#6ec6ff" />
                    </div>
                    {lastCap.pcap_file && (
                        <div className="pcap-file-box">
                            📁 <span style={{ color: '#e6edf3', fontFamily: 'monospace' }}>{lastCap.pcap_file}</span>
                        </div>
                    )}
                </div>
            )}

            {/* Empty state */}
            {!isActive && !lastCap && packets.length === 0 && (
                <div className="panel">
                    <div className="empty-state">
                        <div className="empty-state-icon">
                            <MonitorSpeaker size={32} />
                        </div>
                        <h3 className="empty-state-title">No capture running</h3>
                        <p className="empty-state-desc">
                            Select a network interface above and click <span style={{ color: '#22c55e', fontWeight: 600 }}>Start Capture</span> to begin monitoring traffic.
                        </p>
                        <p style={{ color: '#484f58', fontSize: '0.75rem', marginTop: '0.75rem' }}>
                            ⚠ API must be started with <span style={{ color: '#f59e0b', fontFamily: 'monospace' }}>sudo</span> for capture to work.
                        </p>
                    </div>
                </div>
            )}

            <style>{`
                @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
                @keyframes glow-pulse {
                    0%, 100% { box-shadow: 0 0 8px rgba(34,197,94,0.2); }
                    50% { box-shadow: 0 0 20px rgba(34,197,94,0.4); }
                }
            `}</style>
        </>
    )
}

export default Capture
