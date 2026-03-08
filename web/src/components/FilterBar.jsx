/**
 * Shared FilterBar component used by Connections and Alerts pages.
 * Provides a consistent search/filter UI with:
 *  - Search input
 *  - Protocol dropdown
 *  - Optional extra dropdowns/inputs (via `children`)
 *  - Per-page selector
 *  - Optional clear-all button
 *  - Date range row with quick presets + custom inputs
 */
import { useState, useEffect } from 'react'
import { Search, Filter, Calendar } from 'lucide-react'
import DateTimePicker from './DateTimePicker'

const DATE_PRESETS = [
    ['1h', 'Last hour'],
    ['today', 'Today'],
    ['yesterday', 'Yesterday'],
    ['7d', '7 days'],
    ['30d', '30 days'],
    ['all', 'All time'],
]

const computePreset = (label) => {
    const now = new Date()
    const pad = n => String(n).padStart(2, '0')
    const fmt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`

    switch (label) {
        case 'today': {
            const d = new Date(now)
            d.setHours(0, 0, 0, 0)
            return { from: fmt(d), to: '' }
        }
        case 'yesterday': {
            const y = new Date(now); y.setDate(y.getDate() - 1)
            y.setHours(0, 0, 0, 0)
            const yEnd = new Date(y); yEnd.setHours(23, 59, 0, 0)
            return { from: fmt(y), to: fmt(yEnd) }
        }
        case '7d': {
            const d = new Date(now); d.setDate(d.getDate() - 7)
            return { from: fmt(d), to: '' }
        }
        case '30d': {
            const d = new Date(now); d.setDate(d.getDate() - 30)
            return { from: fmt(d), to: '' }
        }
        case '1h': {
            const d = new Date(now.getTime() - 3600000)
            return { from: fmt(d), to: '' }
        }
        case 'all': default: return { from: '', to: '' }
    }
}

const FilterBar = ({
    // Search
    search,
    onSearchChange,
    searchPlaceholder = 'Search…',

    // Protocol
    proto,
    onProtoChange,
    protocols = [],
    protoActiveColor = '#3b82f6',

    // Per-page
    perPage,
    onPerPageChange,

    // Date range
    dateFrom,
    dateTo,
    onDateFromChange,
    onDateToChange,

    // Clear all
    hasFilters = false,
    onClearAll,

    // Extra filters rendered between protocol and per-page
    children,
}) => {
    const [activePreset, setActivePreset] = useState('all')

    const handlePreset = (key) => {
        const { from, to } = computePreset(key)
        onDateFromChange(from)
        onDateToChange(to)
        setActivePreset(key)
    }

    const handleCustomFrom = (val) => {
        onDateFromChange(val)
        setActivePreset(null)
    }

    const handleCustomTo = (val) => {
        onDateToChange(val)
        setActivePreset(null)
    }

    // Sync preset highlight when dates are cleared externally (e.g. parent's Clear All)
    useEffect(() => {
        if (!dateFrom && !dateTo) setActivePreset('all')
    }, [dateFrom, dateTo])

    return (
        <>
            {/* ── Row 1: Search + Protocol + Extra + Per Page ── */}
            <div className="filter-row">
                <div className="search-wrap">
                    <Search size={15} className="form-input-icon" />
                    <input
                        type="text"
                        placeholder={searchPlaceholder}
                        value={search}
                        onChange={e => onSearchChange(e.target.value)}
                        className="form-input"
                        style={{ width: '100%', paddingLeft: '2.2rem' }}
                    />
                </div>

                <div className="icon-select-wrap">
                    <Filter size={14} className="form-input-icon" />
                    <select
                        value={proto}
                        onChange={e => onProtoChange(e.target.value)}
                        className="form-select"
                        style={{ paddingLeft: '2.2rem', color: proto ? protoActiveColor : undefined }}
                    >
                        <option value="">All protocols</option>
                        {protocols.map(p => <option key={p} value={p}>{p}</option>)}
                    </select>
                </div>

                {children}

                <select
                    value={perPage}
                    onChange={e => onPerPageChange(Number(e.target.value))}
                    className="form-select"
                >
                    <option value={25}>25 / page</option>
                    <option value={50}>50 / page</option>
                    <option value={100}>100 / page</option>
                    <option value={200}>200 / page</option>
                </select>
            </div>

            {/* ── Row 2: Date Range ── */}
            <div className="filter-row-date">
                <Calendar size={14} className="text-muted" style={{ flexShrink: 0 }} />

                <div className="flex-row gap-sm">
                    {DATE_PRESETS.map(([key, label]) => (
                        <button
                            key={key}
                            onClick={() => handlePreset(key)}
                            className={`btn-preset${activePreset === key ? ' active' : (!dateFrom && !dateTo && key === 'all' && !activePreset ? ' active' : '')}`}
                        >
                            {label}
                        </button>
                    ))}
                </div>

                <div className="divider-v" />

                <div className="flex-row gap-sm" style={{ alignItems: 'center' }}>
                    <span className="text-xs text-muted">From</span>
                    <DateTimePicker
                        value={dateFrom}
                        onChange={handleCustomFrom}
                        label="From"
                    />
                    <span className="text-xs text-muted">To</span>
                    <DateTimePicker
                        value={dateTo}
                        onChange={handleCustomTo}
                        label="To"
                    />
                    {(dateFrom || dateTo) && (
                        <button
                            onClick={() => {
                                onDateFromChange(''); onDateToChange(''); setActivePreset('all')
                                if (onClearAll) onClearAll()
                            }}
                            className="btn-ghost"
                        >
                            ✕ Clear
                        </button>
                    )}
                </div>
            </div>
        </>
    )
}

export default FilterBar
