import React, { useEffect, useState } from 'react';
import { fetchStats } from '../../services/api';
import { ShieldAlert, Database, Lock, Globe } from 'lucide-react';
import '../../styles/CyberAesthetics.css';

const StatCard = ({ icon: Icon, title, value, color }) => (
    <div className="cyber-card" style={{ borderLeft: `4px solid ${color}` }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
                <h3 style={{ color: '#8a8a8a', fontSize: '0.8rem', margin: 0 }}>{title}</h3>
                <span style={{ fontSize: '2rem', fontWeight: 'bold', color: '#e0e0e0' }}>{value}</span>
            </div>
            <Icon size={32} color={color} />
        </div>
    </div>
);

const Dashboard = () => {
    const [stats, setStats] = useState(null);

    useEffect(() => {
        fetchStats().then(setStats).catch(console.error);
    }, []);

    if (!stats) return <div>Loading Neural Link...</div>;

    return (
        <div className="cyber-container">
            <header style={{ marginBottom: '2rem', borderBottom: '1px solid #333', paddingBottom: '1rem' }}>
                <h1 className="glitch-text" style={{ fontSize: '2.5rem' }}>THREATLUMEN NEXUS</h1>
                <p style={{ color: 'var(--primary-neon)' }}>// UNCLASSIFIED // THREAT INTELLIGENCE FEED</p>
            </header>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px' }}>
                <StatCard
                    icon={Database}
                    title="TOTAL INTEL"
                    value={stats.total_threats}
                    color="var(--primary-neon)"
                />
                <StatCard
                    icon={ShieldAlert}
                    title="CRITICAL"
                    value={stats.critical_count}
                    color="var(--alert-red)"
                />
                <StatCard
                    icon={Lock}
                    title="RANSOMWARE"
                    value={stats.ransomware_count}
                    color="var(--warning-orange)"
                />
                <StatCard
                    icon={Globe}
                    title="SOURCES"
                    value={stats.sources_count}
                    color="var(--secondary-neon)"
                />
            </div>
        </div>
    );
};

export default Dashboard;
