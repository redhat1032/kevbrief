import React from 'react';
import Dashboard from './components/Dashboard/Dashboard';
import ThreatFeed from './components/Feed/ThreatFeed';
import './styles/CyberAesthetics.css';

function App() {
  return (
    <div className="App">
      <div style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        background: 'radial-gradient(circle at 50% 50%, #1a1a2e 0%, #050507 100%)',
        zIndex: -1
      }} />
      <Dashboard />
      <ThreatFeed />
    </div>
  );
}

export default App;
