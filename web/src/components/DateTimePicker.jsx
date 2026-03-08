/**
 * Custom DateTimePicker with visual date calendar + time selector.
 * Stores value in "YYYY-MM-DD HH:MM" format (space separated).
 */
import { useState, useRef, useEffect } from 'react'
import { Calendar, ChevronLeft, ChevronRight, Clock, X } from 'lucide-react'

const pad = n => String(n).padStart(2, '0')
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
const DAYS = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa']

const parseValue = (val) => {
    if (!val) return { year: 0, month: 0, day: 0, hour: 0, minute: 0 }
    // Handle both "YYYY-MM-DD HH:MM" and "YYYY-MM-DDTHH:MM"
    const normalized = val.replace('T', ' ')
    const [datePart, timePart] = normalized.split(' ')
    const [y, m, d] = datePart.split('-').map(Number)
    const [h, min] = (timePart || '00:00').split(':').map(Number)
    return { year: y, month: m - 1, day: d, hour: h, minute: min }
}

const formatValue = (year, month, day, hour, minute) =>
    `${year}-${pad(month + 1)}-${pad(day)} ${pad(hour)}:${pad(minute)}`

const DateTimePicker = ({ value, onChange, label = 'Date' }) => {
    const [open, setOpen] = useState(false)
    const [view, setView] = useState('date') // 'date' | 'time'
    const ref = useRef(null)

    const now = new Date()
    const parsed = value ? parseValue(value) : null
    const [viewYear, setViewYear] = useState(parsed?.year || now.getFullYear())
    const [viewMonth, setViewMonth] = useState(parsed?.month ?? now.getMonth())
    const [selectedHour, setSelectedHour] = useState(parsed?.hour ?? 0)
    const [selectedMinute, setSelectedMinute] = useState(parsed?.minute ?? 0)

    // Update local state when value changes externally (e.g. presets)
    useEffect(() => {
        if (value) {
            const p = parseValue(value)
            setViewYear(p.year)
            setViewMonth(p.month)
            setSelectedHour(p.hour)
            setSelectedMinute(p.minute)
        }
    }, [value])

    // Close on outside click
    useEffect(() => {
        const handler = (e) => {
            if (ref.current && !ref.current.contains(e.target)) setOpen(false)
        }
        if (open) document.addEventListener('mousedown', handler)
        return () => document.removeEventListener('mousedown', handler)
    }, [open])

    const getDaysInMonth = (y, m) => new Date(y, m + 1, 0).getDate()
    const getFirstDayOfMonth = (y, m) => new Date(y, m, 1).getDay()

    const prevMonth = () => {
        if (viewMonth === 0) { setViewMonth(11); setViewYear(y => y - 1) }
        else setViewMonth(m => m - 1)
    }
    const nextMonth = () => {
        if (viewMonth === 11) { setViewMonth(0); setViewYear(y => y + 1) }
        else setViewMonth(m => m + 1)
    }

    const selectDay = (day) => {
        const newVal = formatValue(viewYear, viewMonth, day, selectedHour, selectedMinute)
        onChange(newVal)
        setView('time') // After picking date, show time picker
    }

    const selectTime = (h, m) => {
        setSelectedHour(h)
        setSelectedMinute(m)
        if (parsed && parsed.year) {
            onChange(formatValue(parsed.year, parsed.month, parsed.day, h, m))
        }
    }

    const displayText = value
        ? (() => {
            const p = parseValue(value)
            return `${pad(p.day)}/${pad(p.month + 1)}/${p.year}, ${pad(p.hour)}:${pad(p.minute)}`
        })()
        : 'Select date & time'

    const daysInMonth = getDaysInMonth(viewYear, viewMonth)
    const firstDay = getFirstDayOfMonth(viewYear, viewMonth)

    const calendarDays = []
    for (let i = 0; i < firstDay; i++) calendarDays.push(null)
    for (let d = 1; d <= daysInMonth; d++) calendarDays.push(d)

    const hours = Array.from({ length: 24 }, (_, i) => i)
    const minutes = [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55]

    return (
        <div ref={ref} style={{ position: 'relative', display: 'inline-flex' }}>
            {/* Trigger button */}
            <button
                type="button"
                onClick={() => { setOpen(!open); setView('date') }}
                className="form-input date-input"
                style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    cursor: 'pointer', textAlign: 'left',
                    color: value ? '#c0c0c0' : '#484f58',
                    fontSize: '0.82rem', whiteSpace: 'nowrap',
                    minWidth: '190px', padding: '5px 10px',
                }}
            >
                <Calendar size={13} style={{ flexShrink: 0, opacity: 0.6 }} />
                {displayText}
            </button>

            {/* Dropdown */}
            {open && (
                <div style={{
                    position: 'absolute', top: 'calc(100% + 6px)', left: 0,
                    zIndex: 100, minWidth: '280px',
                    background: '#161b22', border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '12px', boxShadow: '0 12px 40px rgba(0,0,0,0.5)',
                    overflow: 'hidden',
                    animation: 'fadeIn 0.15s ease',
                }}>
                    {/* Tab header */}
                    <div style={{
                        display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.06)',
                    }}>
                        <button
                            onClick={() => setView('date')}
                            style={{
                                flex: 1, padding: '8px', fontSize: '0.78rem', fontWeight: 600,
                                background: view === 'date' ? 'rgba(139,92,246,0.1)' : 'transparent',
                                color: view === 'date' ? '#a78bfa' : '#7d8590',
                                border: 'none', cursor: 'pointer',
                                borderBottom: view === 'date' ? '2px solid #8b5cf6' : '2px solid transparent',
                                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '5px',
                            }}
                        >
                            <Calendar size={13} /> Date
                        </button>
                        <button
                            onClick={() => setView('time')}
                            style={{
                                flex: 1, padding: '8px', fontSize: '0.78rem', fontWeight: 600,
                                background: view === 'time' ? 'rgba(139,92,246,0.1)' : 'transparent',
                                color: view === 'time' ? '#a78bfa' : '#7d8590',
                                border: 'none', cursor: 'pointer',
                                borderBottom: view === 'time' ? '2px solid #8b5cf6' : '2px solid transparent',
                                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '5px',
                            }}
                        >
                            <Clock size={13} /> Time
                        </button>
                    </div>

                    {view === 'date' ? (
                        /* ── Calendar View ── */
                        <div style={{ padding: '10px' }}>
                            {/* Month/Year nav */}
                            <div style={{
                                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                marginBottom: '8px',
                            }}>
                                <button onClick={prevMonth} style={{
                                    background: 'rgba(255,255,255,0.05)', border: 'none',
                                    color: '#7d8590', cursor: 'pointer', padding: '4px',
                                    borderRadius: '6px', display: 'flex',
                                }}><ChevronLeft size={16} /></button>
                                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#e6edf3' }}>
                                    {MONTHS[viewMonth]} {viewYear}
                                </span>
                                <button onClick={nextMonth} style={{
                                    background: 'rgba(255,255,255,0.05)', border: 'none',
                                    color: '#7d8590', cursor: 'pointer', padding: '4px',
                                    borderRadius: '6px', display: 'flex',
                                }}><ChevronRight size={16} /></button>
                            </div>

                            {/* Day headers */}
                            <div style={{
                                display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)',
                                gap: '2px', marginBottom: '4px',
                            }}>
                                {DAYS.map(d => (
                                    <div key={d} style={{
                                        fontSize: '0.68rem', fontWeight: 600, color: '#484f58',
                                        textAlign: 'center', padding: '4px 0',
                                    }}>{d}</div>
                                ))}
                            </div>

                            {/* Days grid */}
                            <div style={{
                                display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)',
                                gap: '2px',
                            }}>
                                {calendarDays.map((day, i) => {
                                    if (!day) return <div key={`e${i}`} />
                                    const isSelected = parsed &&
                                        parsed.year === viewYear &&
                                        parsed.month === viewMonth &&
                                        parsed.day === day
                                    const isToday =
                                        now.getFullYear() === viewYear &&
                                        now.getMonth() === viewMonth &&
                                        now.getDate() === day
                                    return (
                                        <button
                                            key={day}
                                            onClick={() => selectDay(day)}
                                            style={{
                                                width: '34px', height: '34px',
                                                borderRadius: '8px', border: 'none',
                                                fontSize: '0.78rem', fontWeight: isSelected ? 700 : 400,
                                                cursor: 'pointer',
                                                background: isSelected ? '#8b5cf6'
                                                    : isToday ? 'rgba(139,92,246,0.15)' : 'transparent',
                                                color: isSelected ? '#fff' : isToday ? '#a78bfa' : '#c0c0c0',
                                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                transition: 'background 0.1s',
                                                margin: '0 auto',
                                            }}
                                            onMouseEnter={e => { if (!isSelected) e.target.style.background = 'rgba(255,255,255,0.06)' }}
                                            onMouseLeave={e => { if (!isSelected) e.target.style.background = isToday ? 'rgba(139,92,246,0.15)' : 'transparent' }}
                                        >
                                            {day}
                                        </button>
                                    )
                                })}
                            </div>
                        </div>
                    ) : (
                        /* ── Time View ── */
                        <div style={{ padding: '10px' }}>
                            <div style={{
                                display: 'flex', gap: '10px', alignItems: 'flex-start',
                            }}>
                                {/* Hours */}
                                <div style={{ flex: 1 }}>
                                    <div style={{
                                        fontSize: '0.7rem', fontWeight: 600, color: '#484f58',
                                        textTransform: 'uppercase', letterSpacing: '0.05em',
                                        marginBottom: '6px', textAlign: 'center',
                                    }}>Hour</div>
                                    <div style={{
                                        maxHeight: '200px', overflowY: 'auto',
                                        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
                                        gap: '3px',
                                        scrollbarWidth: 'thin',
                                        scrollbarColor: 'rgba(255,255,255,0.1) transparent',
                                    }}>
                                        {hours.map(h => (
                                            <button
                                                key={h}
                                                onClick={() => selectTime(h, selectedMinute)}
                                                style={{
                                                    padding: '6px 4px', borderRadius: '6px', border: 'none',
                                                    fontSize: '0.78rem', cursor: 'pointer',
                                                    background: selectedHour === h ? '#8b5cf6' : 'transparent',
                                                    color: selectedHour === h ? '#fff' : '#c0c0c0',
                                                    fontWeight: selectedHour === h ? 700 : 400,
                                                    transition: 'background 0.1s',
                                                }}
                                                onMouseEnter={e => { if (selectedHour !== h) e.target.style.background = 'rgba(255,255,255,0.06)' }}
                                                onMouseLeave={e => { if (selectedHour !== h) e.target.style.background = 'transparent' }}
                                            >
                                                {pad(h)}
                                            </button>
                                        ))}
                                    </div>
                                </div>

                                {/* Divider */}
                                <div style={{
                                    width: '1px', background: 'rgba(255,255,255,0.06)',
                                    alignSelf: 'stretch', margin: '20px 0',
                                }} />

                                {/* Minutes */}
                                <div style={{ flex: 1 }}>
                                    <div style={{
                                        fontSize: '0.7rem', fontWeight: 600, color: '#484f58',
                                        textTransform: 'uppercase', letterSpacing: '0.05em',
                                        marginBottom: '6px', textAlign: 'center',
                                    }}>Minute</div>
                                    <div style={{
                                        display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)',
                                        gap: '3px',
                                    }}>
                                        {minutes.map(m => (
                                            <button
                                                key={m}
                                                onClick={() => selectTime(selectedHour, m)}
                                                style={{
                                                    padding: '6px 4px', borderRadius: '6px', border: 'none',
                                                    fontSize: '0.78rem', cursor: 'pointer',
                                                    background: selectedMinute === m ? '#8b5cf6' : 'transparent',
                                                    color: selectedMinute === m ? '#fff' : '#c0c0c0',
                                                    fontWeight: selectedMinute === m ? 700 : 400,
                                                    transition: 'background 0.1s',
                                                }}
                                                onMouseEnter={e => { if (selectedMinute !== m) e.target.style.background = 'rgba(255,255,255,0.06)' }}
                                                onMouseLeave={e => { if (selectedMinute !== m) e.target.style.background = 'transparent' }}
                                            >
                                                :{pad(m)}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            {/* Current selection display */}
                            {parsed && parsed.year > 0 && (
                                <div style={{
                                    marginTop: '10px', padding: '8px',
                                    background: 'rgba(139,92,246,0.08)',
                                    borderRadius: '8px', textAlign: 'center',
                                    fontSize: '0.85rem', color: '#a78bfa', fontWeight: 600,
                                }}>
                                    {pad(selectedHour)}:{pad(selectedMinute)}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Done button */}
                    <div style={{
                        padding: '8px 10px',
                        borderTop: '1px solid rgba(255,255,255,0.06)',
                        display: 'flex', justifyContent: 'flex-end',
                    }}>
                        <button
                            onClick={() => setOpen(false)}
                            style={{
                                padding: '5px 16px', fontSize: '0.78rem', fontWeight: 600,
                                background: 'rgba(139,92,246,0.15)', color: '#a78bfa',
                                border: '1px solid rgba(139,92,246,0.3)',
                                borderRadius: '6px', cursor: 'pointer',
                            }}
                        >
                            Done
                        </button>
                    </div>
                </div>
            )}
        </div>
    )
}

export default DateTimePicker
