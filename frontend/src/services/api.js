const API_BASE = 'http://localhost:8000/api';

export const fetchThreats = async (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.tag) params.append('tag', filters.tag);
    if (filters.severity) params.append('severity', filters.severity);

    const response = await fetch(`${API_BASE}/threats?${params.toString()}`);
    if (!response.ok) throw new Error('Failed to fetch threats');
    return response.json();
};

export const fetchStats = async () => {
    const response = await fetch(`${API_BASE}/stats`);
    if (!response.ok) throw new Error('Failed to fetch stats');
    return response.json();
};
