import { useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { useSession } from '../context/SessionContext'
import Sidebar from './Sidebar'
import { X, Database } from 'lucide-react'

const Layout = () => {
    const { sessionId, sessionInfo, unloadSession } = useSession()
    const location = useLocation()
    const isCaptureRoute = location.pathname === '/capture'
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

    const fmtTime = (isoStr) => {
        if (!isoStr) return ''
        const d = new Date(isoStr)
        const pad = n => String(n).padStart(2, '0')
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
    }

    return (
        <div className="layout">
            <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(c => !c)} />
            <main className="main-content fade-in">
                {/* Session banner — shown when a session is loaded (except on Capture page) */}
                {sessionId && !isCaptureRoute && (
                    <div className="session-banner">
                        <div className="session-banner-icon">
                            <Database size={14} color="#8b5cf6" />
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                            <span className="session-banner-title">
                                SESSION #{sessionId}
                            </span>
                            {sessionInfo && (
                                <span className="session-banner-meta">
                                    {sessionInfo.interface && <span className="mono" style={{ color: '#3b82f6' }}>{sessionInfo.interface}</span>}
                                    {sessionInfo.start_time && <span style={{ marginLeft: '0.5rem' }}>· {fmtTime(sessionInfo.start_time)}</span>}
                                </span>
                            )}
                            <span className="session-banner-note">
                                Viewing session data only
                            </span>
                        </div>
                        <button onClick={unloadSession} className="session-banner-unload">
                            <X size={12} />
                            Unload
                        </button>
                    </div>
                )}
                <Outlet />
            </main>
        </div>
    )
}

export default Layout
