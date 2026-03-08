import { useState, useEffect, useRef, useCallback } from 'react'
import { ShieldAlert, X, ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

const API = 'http://localhost:8000'
const TOAST_DURATION = 8000 // ms

const SEV_CONFIG = {
    high: {
        color: '#ef4444',
        glow: 'rgba(239,68,68,0.25)',
        bg: 'rgba(239,68,68,0.06)',
        border: 'rgba(239,68,68,0.3)',
        label: 'CRITICAL',
        pulse: true,
    },
    medium: {
        color: '#f59e0b',
        glow: 'rgba(245,158,11,0.2)',
        bg: 'rgba(245,158,11,0.05)',
        border: 'rgba(245,158,11,0.28)',
        label: 'WARNING',
        pulse: false,
    },
    low: {
        color: '#3b82f6',
        glow: 'rgba(59,130,246,0.18)',
        bg: 'rgba(59,130,246,0.04)',
        border: 'rgba(59,130,246,0.22)',
        label: 'INFO',
        pulse: false,
    },
}

const Toast = ({ toast, onDismiss }) => {
    const navigate = useNavigate()
    const [progress, setProgress] = useState(100)
    const [entering, setEntering] = useState(true)
    const [leaving, setLeaving] = useState(false)
    const intervalRef = useRef(null)

    const cfg = SEV_CONFIG[toast.severity] || SEV_CONFIG.low

    const handleDismiss = useCallback(() => {
        setLeaving(true)
        setTimeout(() => onDismiss(toast.id), 350)
    }, [toast.id, onDismiss])

    useEffect(() => {
        const entranceTimer = setTimeout(() => setEntering(false), 50)
        const step = 100 / (TOAST_DURATION / 50)
        intervalRef.current = setInterval(() => {
            setProgress(p => {
                if (p <= 0) {
                    clearInterval(intervalRef.current)
                    handleDismiss()
                    return 0
                }
                return p - step
            })
        }, 50)

        return () => {
            clearTimeout(entranceTimer)
            clearInterval(intervalRef.current)
        }
    }, [handleDismiss])

    const pauseProgress = () => clearInterval(intervalRef.current)
    const resumeProgress = () => {
        const step = 100 / (TOAST_DURATION / 50)
        intervalRef.current = setInterval(() => {
            setProgress(p => {
                if (p <= 0) { handleDismiss(); return 0 }
                return p - step
            })
        }, 50)
    }

    return (
        <div
            onMouseEnter={pauseProgress}
            onMouseLeave={resumeProgress}
            className="toast-item"
            style={{
                background: cfg.bg,
                border: `1px solid ${cfg.border}`,
                boxShadow: `0 4px 24px rgba(0,0,0,0.5), 0 0 20px ${cfg.glow}`,
                backdropFilter: 'blur(20px)',
                cursor: 'default',
                transition: 'all 0.35s cubic-bezier(0.34, 1.56, 0.64, 1)',
                opacity: entering || leaving ? 0 : 1,
                transform: entering ? 'translateX(120%)' : leaving ? 'translateX(120%)' : 'translateX(0)',
            }}
        >
            {/* Left accent bar */}
            <div className="toast-accent" style={{ background: cfg.color }} />

            {/* Content area */}
            <div className="toast-body">
                {/* Icon */}
                <div className="toast-icon-wrap" style={{
                    background: `${cfg.color}15`,
                    border: `1px solid ${cfg.color}30`,
                    animation: cfg.pulse ? 'toastPulse 2s ease-in-out infinite' : 'none',
                    '--pulse-color': cfg.color,
                }}>
                    <ShieldAlert size={16} color={cfg.color} />
                </div>

                {/* Text block */}
                <div className="toast-content">
                    <div className="toast-top-row">
                        <span className="toast-sev-label" style={{ color: cfg.color }}>
                            {cfg.label}
                        </span>
                        <span className="toast-time">
                            {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                    </div>
                    <div className="toast-title">{toast.title}</div>
                    {toast.meta && (
                        <div className="toast-meta">{toast.meta}</div>
                    )}
                </div>

                {/* Close */}
                <button onClick={() => handleDismiss()} className="toast-close">
                    <X size={14} />
                </button>
            </div>

            {/* Footer */}
            <div className="toast-footer">
                <button
                    onClick={() => { navigate('/alerts'); handleDismiss() }}
                    className="toast-view-btn"
                    style={{ color: cfg.color }}
                >
                    View Alerts <ChevronRight size={12} />
                </button>
            </div>

            {/* Progress bar */}
            <div className="toast-progress-track">
                <div className="toast-progress" style={{
                    width: `${progress}%`,
                    background: `linear-gradient(90deg, ${cfg.color}60, ${cfg.color})`,
                    boxShadow: `0 0 4px ${cfg.color}80`,
                }} />
            </div>
        </div>
    )
}

// ─── Global Toast Manager ──────────────────────────────────────
export const AlertToastProvider = () => {
    const [toasts, setToasts] = useState([])
    const lastAlertId = useRef(0)
    const initialLoad = useRef(true)

    const addToast = useCallback((alert) => {
        setToasts(prev => {
            const next = [{ ...alert, toastId: `${alert.id}-${Date.now()}` }, ...prev].slice(0, 5)
            return next
        })
    }, [])

    const dismissToast = useCallback((toastId) => {
        setToasts(prev => prev.filter(t => t.toastId !== toastId))
    }, [])

    useEffect(() => {
        const check = async () => {
            try {
                const res = await fetch(`${API}/api/alerts/latest`)
                const data = await res.json()
                if (!data.id) return

                if (initialLoad.current) {
                    lastAlertId.current = data.id
                    initialLoad.current = false
                    return
                }

                if (data.id > lastAlertId.current) {
                    lastAlertId.current = data.id
                    addToast(data)
                }
            } catch (e) { /* api offline */ }
        }

        check()
        const id = setInterval(check, 5000)
        return () => clearInterval(id)
    }, [addToast])

    if (toasts.length === 0) return null

    return (
        <>
            <style>{`
                @keyframes toastPulse {
                    0%, 100% { box-shadow: 0 0 8px var(--pulse-color, rgba(239,68,68,0.2)); }
                    50% { box-shadow: 0 0 18px var(--pulse-color, rgba(239,68,68,0.5)); }
                }
            `}</style>

            <div className="toast-container">
                {toasts.map(t => (
                    <Toast key={t.toastId} toast={t} onDismiss={dismissToast} />
                ))}
            </div>
        </>
    )
}

export default AlertToastProvider
