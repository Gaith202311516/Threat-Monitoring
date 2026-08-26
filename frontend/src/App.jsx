import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

// ربط التطبيق بمتغيرات البيئة مع إبقاء قيم افتراضية للتأمين
const API_HOST = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
const API_BASE = `${API_HOST}/api`;
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://127.0.0.1:8000/ws/logs';

export default function App() {
  const [logs, setLogs] = useState([]);
  const [threats, setThreats] = useState([]);
  const [timelineData, setTimelineData] = useState([]);
  const [topSources, setTopSources] = useState([]);
  const [isConnected, setIsConnected] = useState(false);

  // جلب البيانات الأولية والإحصائيات
  const fetchData = async () => {
    try {
      const logsRes = await axios.get(`${API_BASE}/logs/recent`);
      setLogs(logsRes.data);

      const threatsRes = await axios.get(`${API_BASE}/threats`);
      setThreats(threatsRes.data);

      const timelineRes = await axios.get(`${API_BASE}/analytics/timeline`);
      setTimelineData(timelineRes.data.reverse());

      const sourcesRes = await axios.get(`${API_BASE}/analytics/top-sources`);
      setTopSources(sourcesRes.data);
    } catch (err) {
      console.error("Error fetching data:", err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // تحديث الإحصائيات كل 10 ثوانٍ

    const ws = new WebSocket(WS_URL);
    ws.onopen = () => setIsConnected(true);
    ws.onclose = () => setIsConnected(false);

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.event === 'new_log') {
        setLogs((prev) => [data, ...prev.slice(0, 49)]);
      } else if (data.event === 'threat_alert') {
        setThreats((prev) => [data, ...prev]);
      }
    };

    return () => {
      clearInterval(interval);
      ws.close();
    };
  }, []);

  // معالجة التهديد
  const handleResolve = async (id) => {
    try {
      await axios.post(`${API_BASE}/threats/${id}/resolve`);
      setThreats((prev) =>
        prev.map((t) => (t.id === id ? { ...t, is_resolved: true } : t))
      );
    } catch (err) {
      console.error("Error resolving threat:", err);
    }
  };

  // حظر IP مباشر من الواجهة
  const handleBlacklist = async (ip) => {
    try {
      await axios.post(`${API_BASE}/ip/blacklist?ip_address=${ip}`);
      alert(`تم إضافة الـ IP ${ip} إلى القائمة السوداء بنجاح!`);
    } catch (err) {
      console.error("Error blacklisting IP:", err);
    }
  };

  return (
    <div className="dashboard-container">
      <header className="header">
        <h1>🛡️ Real-Time Threat Intelligence System</h1>
        <span className={`status-badge ${isConnected ? 'connected' : 'disconnected'}`}>
          {isConnected ? 'WebSocket: Live' : 'WebSocket: Offline'}
        </span>
      </header>

      {/* الكروت الإحصائية */}
      <div className="stats-grid">
        <div className="stat-card">
          <h4>إجمالي السجلات (Recent Logs)</h4>
          <p>{logs.length}</p>
        </div>
        <div className="stat-card">
          <h4>التهديدات النشطة (Active Threats)</h4>
          <p style={{ color: '#ef4444' }}>
            {threats.filter((t) => !t.is_resolved).length}
          </p>
        </div>
        <div className="stat-card">
          <h4>التهديدات المعالجة (Resolved)</h4>
          <p style={{ color: '#22c55e' }}>
            {threats.filter((t) => t.is_resolved).length}
          </p>
        </div>
      </div>

      {/* قسم الرسم البياني وأعلى المصادر */}
      <div className="main-grid" style={{ marginBottom: '20px' }}>
        <div className="panel" style={{ maxHeight: '320px' }}>
          <h2>📈 Traffic Timeline (Logs / Min)</h2>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <LineChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="time" stroke="#94a3b8" tick={false} />
                <YAxis stroke="#94a3b8" />
                <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                <Line type="monotone" dataKey="log_count" stroke="#38bdf8" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel" style={{ maxHeight: '320px' }}>
          <h2>🎯 Top Attack Source IPs</h2>
          <div className="list-container">
            {topSources.map((source, idx) => (
              <div className="log-item" key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span><strong>{source.source_ip}</strong> ({source.count} logs)</span>
                <button className="resolve-btn" style={{ background: '#ef4444' }} onClick={() => handleBlacklist(source.source_ip)}>
                  Blacklist IP
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* قسم السجلات والتنبيهات الحية */}
      <div className="main-grid">
        <div className="panel">
          <h2>📊 Live Network Logs</h2>
          <div className="list-container">
            {logs.map((log, idx) => (
              <div className="log-item" key={log.id || idx}>
                <strong>IP:</strong> {log.source_ip} | <strong>Event:</strong> {log.event_type}
                <span className={`badge badge-${(log.severity || 'low').toLowerCase()}`}>
                  {log.severity || 'Low'}
                </span>
                <button className="resolve-btn" style={{ background: '#334155', marginLeft: '8px', float: 'right' }} onClick={() => handleBlacklist(log.source_ip)}>
                  Block
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <h2>⚠️ Threat Alerts</h2>
          <div className="list-container">
            {threats.map((threat) => (
              <div className="threat-item" key={threat.id} style={{ opacity: threat.is_resolved ? 0.5 : 1 }}>
                {!threat.is_resolved && (
                  <button className="resolve-btn" onClick={() => handleResolve(threat.id)}>
                    Resolve
                  </button>
                )}
                <strong>Type:</strong> {threat.threat_type} <br />
                <strong>Score:</strong> {threat.threat_score} | <strong>Desc:</strong> {threat.description}
                {threat.is_resolved && <span style={{ color: '#22c55e', marginLeft: '10px' }}>(Resolved)</span>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}