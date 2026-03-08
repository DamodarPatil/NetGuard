import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Network, Shield, Settings, Radio, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import flowsentrixLogo from '../assets/flowsentrix-logo.svg'

const Sidebar = ({ collapsed, onToggle }) => {
    return (
        <aside className={`sidebar ${collapsed ? 'sidebar-collapsed' : ''}`}>
            {/* Toggle row — sits above everything */}
            <div className="sidebar-toggle-row">
                <button
                    onClick={onToggle}
                    className="sidebar-toggle-btn"
                    title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                >
                    {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
                </button>
            </div>

            {/* Brand */}
            <div className="sidebar-brand">
                <div className="sidebar-brand-icon">
                    <img src={flowsentrixLogo} alt="FlowSentrix" width={24} height={24} />
                </div>
                {!collapsed && (
                    <div className="sidebar-brand-text">
                        <h2>FlowSentrix</h2>
                    </div>
                )}
            </div>

            {/* Navigation */}
            <nav className="sidebar-nav">
                <NavLink to="/capture" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    title="Capture">
                    <Radio size={18} />
                    {!collapsed && 'Capture'}
                </NavLink>
                <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end
                    title="Dashboard">
                    <LayoutDashboard size={18} />
                    {!collapsed && 'Dashboard'}
                </NavLink>
                <NavLink to="/connections" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    title="Connections">
                    <Network size={18} />
                    {!collapsed && 'Connections'}
                </NavLink>
                <NavLink to="/alerts" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    title="Alerts">
                    <Shield size={18} />
                    {!collapsed && 'Alerts'}
                </NavLink>
                <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    title="Settings">
                    <Settings size={18} />
                    {!collapsed && 'Settings'}
                </NavLink>
            </nav>
        </aside>
    )
}

export default Sidebar
