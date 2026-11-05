import React, { useEffect, useState } from 'react';
import { fetchThreats } from '../../services/api';
import { ExternalLink, AlertTriangle, Shield } from 'lucide-react';

const SeverityBadge = ({ level }) => {
    let color = '#8a8a8a';
    if (level === 'critical') color = 'var(--alert-red)';
    if (level === 'high') color = 'var(--warning-orange)';
    if (level === 'medium') color = 'var(--primary-neon)';

    return (
        <span style={{
            color: color,
            border: `1px solid ${color}`,
            padding: '2px 8px',
            borderRadius: '4px',
            textTransform: 'uppercase',
            fontSize: '0.7rem',
            fontWeight: 'bold',
            marginLeft: '10px'
        }}>
            {level}
        </span>
    );
};

const ThreatFeed = () => {
    const [threats, setThreats] = useState([]);
    const [filter, setFilter] = useState('');

    useEffect(() => {
        fetchThreats().then(data => {
            setThreats(data.threats);
        }).catch(console.error);
    }, []);

    const filteredThreats = threats.filter(t =>
        t.title.toLowerCase().includes(filter.toLowerCase()) ||
        t.tags.some(tag => tag.toLowerCase().includes(filter.toLowerCase()))
    );

    return (
        <div className="cyber-container">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h2 style={{ color: 'var(--text-main)' }}> LATEST INTERCEPTS</h2>
                <input
                    type="text"
                    placeholder="SEARCH DATALINK..."
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    style={{
                        background: 'transparent',
                        border: '1px solid var(--primary-neon)',
                        color: 'var(--primary-neon)',
                        padding: '10px',
                        fontFamily: 'inherit',
                        width: '300px'
                    }}
                />
            </div>

            <div style={{ display: 'grid', gap: '15px' }}>
                {filteredThreats.map((threat, idx) => (
                    <div key={idx} className="cyber-card" style={{ borderLeft: threat.severity === 'critical' ? '4px solid var(--alert-red)' : '' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <div style={{ marginBottom: '10px' }}>
                                <span style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>{threat.published_date} | {threat.source}</span>
                                <SeverityBadge level={threat.severity} />
                            </div>
                            {threat.link && (
                                <a href={threat.link} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--primary-neon)' }}>
                                    <ExternalLink size={16} />
                                </a>
                            )}
                        </div>

                        <h3 style={{ margin: '5px 0', fontSize: '1.2rem' }}>{threat.title}</h3>

                        <p style={{ color: '#ccc', fontSize: '0.9rem', lineHeight: '1.5' }}>
                            {threat.description}
                        </p>

                        <div style={{ marginTop: '10px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                            {threat.tags.map(tag => (
                                <span key={tag} style={{ background: 'rgba(255,255,255,0.1)', padding: '2px 6px', fontSize: '0.7rem', borderRadius: '2px' }}>
                                    #{tag}
                                </span>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ThreatFeed;
