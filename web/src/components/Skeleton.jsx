/**
 * Skeleton shimmer components for loading states.
 * Drop-in replacements for data that hasn't loaded yet.
 */

// Single shimmer bar
export const Skeleton = ({ width = '100%', height = '14px', radius = '6px', style }) => (
    <div className="skeleton" style={{ width, height, borderRadius: radius, ...style }} />
)

// Skeleton row for tables (matches data-table column structure)
export const SkeletonTableRow = ({ cols = 8 }) => (
    <tr className="skeleton-row">
        {Array.from({ length: cols }, (_, i) => (
            <td key={i} style={{ padding: '0.55rem 1rem' }}>
                <Skeleton
                    width={i === 0 || i === 1 ? '120px' : i === cols - 1 ? '100px' : '60px'}
                    height="12px"
                />
            </td>
        ))}
    </tr>
)

// Skeleton stat card
export const SkeletonCard = () => (
    <div className="skeleton-card">
        <Skeleton width="80px" height="10px" style={{ marginBottom: '0.75rem' }} />
        <Skeleton width="50px" height="24px" style={{ marginBottom: '0.5rem' }} />
        <Skeleton width="100px" height="10px" />
    </div>
)

// Table skeleton (header + rows)
export const SkeletonTable = ({ rows = 8, cols = 8 }) => (
    <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="data-table">
            <thead>
                <tr>
                    {Array.from({ length: cols }, (_, i) => (
                        <th key={i}><Skeleton width="60px" height="10px" /></th>
                    ))}
                </tr>
            </thead>
            <tbody>
                {Array.from({ length: rows }, (_, i) => (
                    <SkeletonTableRow key={i} cols={cols} />
                ))}
            </tbody>
        </table>
    </div>
)

// Empty state with icon, message, and optional CTA
export const EmptyState = ({ icon: Icon, title, description, action, onAction }) => (
    <div className="empty-state">
        <div className="empty-state-icon">
            {Icon && <Icon size={36} />}
        </div>
        <h3 className="empty-state-title">{title}</h3>
        {description && <p className="empty-state-desc">{description}</p>}
        {action && onAction && (
            <button className="btn-primary empty-state-btn" onClick={onAction}>
                {action}
            </button>
        )}
    </div>
)
