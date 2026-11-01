'use client'

import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleHelp,
  Clock3,
  FileUp,
  Filter,
  FileText,
  LoaderCircle,
  LogOut,
  Network,
  Radar,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Upload,
  UsersRound,
  X,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { ChangeEvent, FormEvent, useCallback, useEffect, useState } from 'react'

type View = 'overview' | 'events' | 'alerts' | 'incidents' | 'ingestion' | 'analysts'
type NetworkEvent = {
  event_id: string
  timestamp: string
  source_ip: string
  destination_ip: string
  destination_port: number | null
  protocol: string
  tcp_flags: string[] | null
  sensor_type: string
  scenario_id: string | null
  connection_state: string | null
}
type Alert = {
  alert_id: string
  rule_id: string
  rule_name: string
  source_ip: string
  destination_ip: string
  severity: string
  confidence: number
  first_seen: string
  last_seen: string
  event_count: number
  unique_ports: number[]
  detection_reason: string
  status: string
  scan_type: string
  assigned_to?: string | null
}
type Summary = {
  total_events: number
  total_alerts: number
  critical_alerts: number
  high_alerts: number
  unique_source_ips: number
  targeted_hosts: number
  unique_destination_ports: number
  simulated_events: number
  active_incidents: number
  severity_distribution: Record<string, number>
  data_mode: string
}
type Incident = {
  incident_id: string
  title: string
  status: string
  assigned_to: string | null
  alert_ids: string[]
  updated_at: string
}
type Analyst = { username: string; role: string }

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000').replace(/\/$/, '')
const NAV_ITEMS: { id: View; label: string; icon: typeof Radar }[] = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'events', label: 'Network events', icon: Network },
  { id: 'alerts', label: 'Security alerts', icon: ShieldAlert },
  { id: 'incidents', label: 'Incidents', icon: Siren },
  { id: 'ingestion', label: 'Log ingestion', icon: FileUp },
  { id: 'analysts', label: 'Analyst management', icon: UsersRound },
]

function csvCell(value: unknown): string {
  const raw = String(value ?? '')
  const text = /^[\t\r\n ]*[=+\-@]/.test(raw) ? `'${raw}` : raw
  return `"${text.replaceAll('"', '""')}"`
}

function downloadCsv(filename: string, rows: string[][]) {
  const content = rows.map((row) => row.map(csvCell).join(',')).join('\r\n')
  const link = document.createElement('a')
  link.href = URL.createObjectURL(new Blob([content], { type: 'text/csv;charset=utf-8' }))
  link.download = filename
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(link.href), 1000)
}

function formatTime(value: string) {
  return new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function severityClass(value: string) {
  return `severity severity-${value.toLowerCase()}`
}

export default function Home() {
  const [view, setView] = useState<View>('overview')
  const [summary, setSummary] = useState<Summary | null>(null)
  const [events, setEvents] = useState<NetworkEvent[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [analysts, setAnalysts] = useState<Analyst[]>([])
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<'soc_analyst' | 'read_only_viewer'>('soc_analyst')
  const [loading, setLoading] = useState(true)
  const [authReady, setAuthReady] = useState(false)
  const [identity, setIdentity] = useState<{ username: string; role: string } | null>(null)
  const [csrfToken, setCsrfToken] = useState('')
  const [loginUsername, setLoginUsername] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [authMessage, setAuthMessage] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('All severities')
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [selectedEvidence, setSelectedEvidence] = useState<NetworkEvent[]>([])
  const [assignedAnalyst, setAssignedAnalyst] = useState('')
  const [resolutionText, setResolutionText] = useState('')
  const [ingestFormat, setIngestFormat] = useState('zeek')
  const [ingestFile, setIngestFile] = useState<File | null>(null)
  const [ingestMessage, setIngestMessage] = useState('')
  const [busyAction, setBusyAction] = useState(false)

  const apiFetch = useCallback(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const headers = new Headers(init.headers)
    if (init.method && !['GET', 'HEAD', 'OPTIONS'].includes(init.method.toUpperCase()) && csrfToken) {
      headers.set('X-CSRF-Token', csrfToken)
    }
    const response = await fetch(input, { ...init, headers, credentials: 'include' })
    if (response.status === 401) {
      setIdentity(null)
      setCsrfToken('')
    }
    return response
  }, [csrfToken])

  const refresh = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true)
    else setLoading(true)
    try {
      const [summaryResponse, eventResponse, alertResponse, incidentResponse] = await Promise.all([
        apiFetch(`${API_BASE}/api/dashboard/summary`, { cache: 'no-store' }),
        apiFetch(`${API_BASE}/api/events?limit=500`, { cache: 'no-store' }),
        apiFetch(`${API_BASE}/api/alerts?limit=500`, { cache: 'no-store' }),
        apiFetch(`${API_BASE}/api/incidents?limit=100`, { cache: 'no-store' }),
      ])
      if (![summaryResponse, eventResponse, alertResponse, incidentResponse].every((response) => response.ok)) {
        throw new Error('The local API returned an unsuccessful response.')
      }
      const [nextSummary, eventPayload, alertPayload, incidentPayload] = await Promise.all([
        summaryResponse.json(),
        eventResponse.json(),
        alertResponse.json(),
        incidentResponse.json(),
      ])
      setSummary(nextSummary)
      setEvents(eventPayload.items)
      setAlerts(alertPayload.items)
      setIncidents(incidentPayload.items)
      setError('')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to load SOC data.')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [apiFetch])

  useEffect(() => {
    let active = true
    async function restoreSession() {
      try {
        const response = await fetch(`${API_BASE}/api/auth/me`, { credentials: 'include', cache: 'no-store' })
        if (!response.ok) return
        const [current, csrfResponse] = await Promise.all([
          response.json(),
          fetch(`${API_BASE}/api/auth/csrf`, { credentials: 'include', cache: 'no-store' }),
        ])
        if (!csrfResponse.ok) throw new Error('Unable to initialize the secure session.')
        const csrf = await csrfResponse.json()
        if (active) {
          setIdentity(current)
          setCsrfToken(csrf.csrf_token)
        }
      } catch (reason) {
        if (active) setAuthMessage(reason instanceof Error ? reason.message : 'Unable to restore the session.')
      } finally {
        if (active) setAuthReady(true)
      }
    }
    void restoreSession()
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    if (!identity) return
    const initialRefresh = window.setTimeout(() => void refresh(), 0)
    const timer = window.setInterval(() => void refresh(true), 15000)
    return () => {
      window.clearTimeout(initialRefresh)
      window.clearInterval(timer)
    }
  }, [identity, refresh])

  useEffect(() => {
    if (!identity) return
    const timer = window.setTimeout(() => {
      void apiFetch(`${API_BASE}/api/analysts`, { cache: 'no-store' }).then(async (response) => {
        if (!response.ok) throw new Error('Unable to load analyst accounts.')
        const payload = await response.json()
        setAnalysts(payload.items)
      }).catch((reason) => setAuthMessage(reason instanceof Error ? reason.message : 'Unable to load analyst accounts.'))
    }, 0)
    return () => window.clearTimeout(timer)
  }, [identity, apiFetch])

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusyAction(true)
    setAuthMessage('')
    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username: loginUsername, password: loginPassword }),
      })
      const result = await response.json()
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Login failed.')
      setIdentity(result.user)
      setCsrfToken(result.csrf_token)
      setLoginPassword('')
    } catch (reason) {
      setAuthMessage(reason instanceof Error ? reason.message : 'Login failed.')
    } finally {
      setBusyAction(false)
      setAuthReady(true)
    }
  }

  async function logout() {
    try {
      const response = await apiFetch(`${API_BASE}/api/auth/logout`, { method: 'POST' })
      if (!response.ok) throw new Error('Logout failed.')
      setIdentity(null)
      setCsrfToken('')
      setSummary(null)
      setEvents([])
      setAlerts([])
      setIncidents([])
    } catch (reason) {
      setAuthMessage(reason instanceof Error ? reason.message : 'Logout failed.')
    }
  }

  async function addAnalyst(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusyAction(true)
    setIngestMessage('')
    try {
      const response = await apiFetch(`${API_BASE}/api/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: newUsername, password: newPassword, role: newRole }),
      })
      const result = await response.json()
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Account creation failed.')
      setNewUsername('')
      setNewPassword('')
      const list = await apiFetch(`${API_BASE}/api/analysts`, { cache: 'no-store' })
      if (!list.ok) throw new Error('Account was created, but refreshing analyst accounts failed.')
      setAnalysts((await list.json()).items)
      setIngestMessage(`Created ${result.role.replaceAll('_', ' ')} account ${result.username}.`)
    } catch (reason) {
      setIngestMessage(reason instanceof Error ? reason.message : 'Account creation failed.')
    } finally {
      setBusyAction(false)
    }
  }

  async function generateDemo() {
    setBusyAction(true)
    setIngestMessage('')
    try {
      const response = await apiFetch(`${API_BASE}/api/demo/generate?scenario=syn&count=40`, { method: 'POST' })
      const result = await response.json()
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Event generation failed.')
      setIngestMessage(`Generated ${result.accepted} simulated events and ${result.alerts.length} alerts.`)
      await refresh(true)
    } catch (reason) {
      setIngestMessage(reason instanceof Error ? reason.message : 'Event generation failed.')
    } finally {
      setBusyAction(false)
    }
  }

  async function uploadLog(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!ingestFile) {
      setIngestMessage('Choose a log file first.')
      return
    }
    setBusyAction(true)
    setIngestMessage('')
    const formData = new FormData()
    formData.append('file', ingestFile)
    try {
      const endpoint = ingestFormat === 'pcap' ? '/api/ingest/pcap' : `/api/ingest/upload?format=${ingestFormat}`
      const response = await apiFetch(`${API_BASE}${endpoint}`, { method: 'POST', body: formData })
      const result = await response.json()
      if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Log ingestion failed validation.')
      const issueSummary = ingestFormat === 'pcap'
        ? `${result.malformed_packets} malformed packets`
        : `${result.parse_error_count} malformed records`
      setIngestMessage(`Parsed ${result.parsed} records; stored ${result.accepted}, skipped ${result.duplicates} duplicates, and found ${issueSummary}.`)
      await refresh(true)
    } catch (reason) {
      setIngestMessage(reason instanceof Error ? reason.message : 'Log ingestion failed.')
    } finally {
      setBusyAction(false)
    }
  }

  async function openAlert(alert: Alert) {
    setSelectedAlert(alert)
    setSelectedEvidence([])
    setAssignedAnalyst(alert.assigned_to ?? '')
    try {
      const response = await apiFetch(`${API_BASE}/api/alerts/${alert.alert_id}`, { cache: 'no-store' })
      if (!response.ok) throw new Error('Unable to load alert evidence.')
      const result = await response.json()
      setSelectedEvidence(result.evidence)
    } catch (reason) {
      setSelectedEvidence([])
      setIngestMessage(reason instanceof Error ? reason.message : 'Unable to load alert evidence.')
    }
  }

  async function updateAlertStatus(status: string) {
    if (!selectedAlert) return
    const response = await apiFetch(`${API_BASE}/api/alerts/${selectedAlert.alert_id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, assigned_to: assignedAnalyst || null }),
    })
    if (!response.ok) throw new Error('Alert update failed.')
    await refresh(true)
    setSelectedAlert((current) => current ? { ...current, status } : current)
  }

  async function createIncident() {
    if (!selectedAlert) return
    const response = await apiFetch(`${API_BASE}/api/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        alert_id: selectedAlert.alert_id,
        title: `${selectedAlert.rule_name} — ${selectedAlert.source_ip}`,
      }),
    })
    if (!response.ok) throw new Error('Incident creation failed.')
    await refresh(true)
    setView('incidents')
    setSelectedAlert(null)
  }

  async function updateIncidentStatus(incidentId: string, status: string) {
    if (status === 'Resolved' && !resolutionText.trim()) {
      throw new Error('Add a resolution note before marking the incident resolved.')
    }
    const response = await apiFetch(`${API_BASE}/api/incidents/${incidentId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, ...(status === 'Resolved' ? { resolution: resolutionText.trim() } : {}) }),
    })
    if (!response.ok) throw new Error('Incident update failed.')
    await refresh(true)
  }

  async function updateIncidentAssignee(incidentId: string, assigned_to: string) {
    const response = await apiFetch(`${API_BASE}/api/incidents/${incidentId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assigned_to: assigned_to || null }),
    })
    if (!response.ok) throw new Error((await response.json()).detail ?? 'Incident assignment failed.')
    await refresh(true)
  }

  const filteredEvents = events.filter((event) => {
    const text = `${event.source_ip} ${event.destination_ip} ${event.destination_port ?? ''} ${event.protocol} ${event.sensor_type}`.toLowerCase()
    return text.includes(query.toLowerCase())
  })
  const filteredAlerts = alerts.filter((alert) => {
    const text = `${alert.rule_name} ${alert.source_ip} ${alert.destination_ip} ${alert.scan_type}`.toLowerCase()
    return text.includes(query.toLowerCase()) && (severityFilter === 'All severities' || alert.severity === severityFilter)
  })
  const timeline = [...events].sort((first, second) => Date.parse(first.timestamp) - Date.parse(second.timestamp)).reduce<{ time: string; label: string; events: number }[]>((points, event) => {
    const bucket = new Date(Math.floor(Date.parse(event.timestamp) / 300000) * 300000)
    const key = bucket.toISOString()
    const label = bucket.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })
    const point = points.find((item) => item.time === key)
    if (point) point.events += 1
    else points.push({ time: key, label, events: 1 })
    return points
  }, []).slice(-12)
  const topSources = Object.entries(events.reduce<Record<string, number>>((counts, event) => {
    counts[event.source_ip] = (counts[event.source_ip] ?? 0) + 1
    return counts
  }, {})).sort((first, second) => second[1] - first[1]).slice(0, 5)

  function exportEvents() {
    downloadCsv('network-events.csv', [['Timestamp', 'Source IP', 'Destination IP', 'Destination Port', 'Protocol', 'Flags', 'Sensor', 'Scenario'], ...filteredEvents.map((event) => [event.timestamp, event.source_ip, event.destination_ip, String(event.destination_port ?? ''), event.protocol, (event.tcp_flags ?? []).join(' '), event.sensor_type, event.scenario_id ?? ''])])
  }

  function exportAlerts() {
    downloadCsv('security-alerts.csv', [['Alert ID', 'Rule', 'Source IP', 'Destination IP', 'Severity', 'Confidence', 'First Seen', 'Last Seen', 'Event Count', 'Scan Type', 'Status'], ...filteredAlerts.map((alert) => [alert.alert_id, alert.rule_name, alert.source_ip, alert.destination_ip, alert.severity, String(alert.confidence), alert.first_seen, alert.last_seen, String(alert.event_count), alert.scan_type, alert.status])])
  }

  const pageTitle = NAV_ITEMS.find((item) => item.id === view)?.label ?? 'Overview'
  const canWrite = identity?.role !== 'read_only_viewer'
  const canManageTeam = ['super_admin', 'security_admin', 'soc_manager'].includes(identity?.role ?? '')

  if (!authReady) {
    return <main className="auth-screen"><div className="loading-state"><LoaderCircle className="spin" size={22} /> Checking secure session</div></main>
  }

  if (!identity) {
    return (
      <main className="auth-screen">
        <form className="auth-card" onSubmit={(event) => void login(event)}>
          <div className="brand-lockup"><span className="brand-mark"><Radar size={22} /></span><span><strong>SENTINELSOC</strong><small>NETWORK DEFENSE PLATFORM</small></span></div>
          <h1>Analyst sign in</h1>
          <p>Sign in with an account created by your SOC administrator.</p>
          {authMessage && <div className="notice notice-error" role="alert">{authMessage}</div>}
          <label className="form-label">Username<input autoComplete="username" required maxLength={64} value={loginUsername} onChange={(event) => setLoginUsername(event.target.value)} /></label>
          <label className="form-label">Password<input type="password" autoComplete="current-password" required value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} /></label>
          <button className="button button-primary" type="submit" disabled={busyAction}>{busyAction ? <LoaderCircle className="spin" size={16} /> : <ShieldCheck size={16} />} Sign in</button>
          <small className="auth-help">Initial administrator setup: run <code>python -m backend.app.admin create-admin</code> in a terminal.</small>
        </form>
      </main>
    )
  }

  return (
    <main className="soc-shell">
      <aside className="sidebar">
        <a href="#overview" className="brand-lockup" onClick={() => setView('overview')}>
          <span className="brand-mark"><Radar size={22} strokeWidth={1.8} /></span>
          <span><strong>SENTINELSOC</strong><small>NETWORK THREAT OPERATIONS</small></span>
        </a>
        <div className="workspace-label">WORKSPACE <span>LOCAL</span></div>
        <nav className="primary-nav" aria-label="Primary navigation">
          {NAV_ITEMS.filter((item) => item.id !== 'analysts' || canManageTeam).map(({ id, label, icon: Icon }) => (
            <button key={id} className={`nav-item ${view === id ? 'active' : ''}`} onClick={() => setView(id)}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
              {id === 'alerts' && alerts.length > 0 && <span className="nav-count">{alerts.length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sensor-card">
            <span className="sensor-pulse" />
            <div><strong>Local sensor</strong><small>API connection {error ? 'interrupted' : 'active'}</small></div>
            {error ? <AlertTriangle size={15} className="text-red" /> : <ShieldCheck size={15} className="text-green" />}
          </div>
          <div className="sidebar-foot">DETECTION LAB <span>v0.1.0</span></div>
        </div>
      </aside>

      <section className="main-column">
        <header className="topbar">
          <div className="crumb"><span>OPERATIONS</span><ChevronRight size={14} /><strong>{pageTitle.toUpperCase()}</strong></div>
          <div className="topbar-actions">
            <span className="live-state"><span /> LOCAL API</span>
            <span className="user-badge">{identity.username} · {identity.role.replaceAll('_', ' ')}</span>
            <button className="icon-button" aria-label="Sign out" title="Sign out" onClick={() => void logout()}><LogOut size={16} /></button>
            <button className="icon-button" aria-label="Refresh data" title="Refresh data" onClick={() => void refresh(true)} disabled={refreshing}>
              <RefreshCw size={16} className={refreshing ? 'spin' : ''} />
            </button>
          </div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS <span className="demo-chip">SIMULATED / OFFLINE DATA</span></div>
              <h1>{view === 'overview' ? 'Threat activity' : pageTitle}</h1>
              <p>{view === 'overview' ? 'Network telemetry, normalized and analyzed locally.' : view === 'events' ? 'Normalized events stored in the local detection database.' : view === 'alerts' ? 'Explainable detections generated from ingested event evidence.' : view === 'incidents' ? 'Track local analyst response and resolution history.' : view === 'analysts' ? 'Manage local analyst accounts and assignments.' : 'Parse offline Zeek, Suricata, and supported UFW syslog files.'}</p>
            </div>
            <div className="heading-actions">
              <span className="updated-label"><Clock3 size={14} /> AUTO-REFRESH 15S</span>
              <a className="button button-secondary" href={`${API_BASE}/api/reports/summary.pdf?period=weekly`}><FileText size={16} /> Weekly PDF</a>
              {canWrite && <button className="button button-primary" onClick={view === 'ingestion' ? () => setIngestMessage('Choose a source format and file below.') : generateDemo} disabled={busyAction}>
                <Activity size={16} /> Generate demo events
              </button>}
            </div>
          </div>

          {error && <div className="notice notice-error"><AlertTriangle size={17} /><div><strong>Cannot reach the local API</strong><p>{error} Start the backend at {API_BASE} to load or generate data.</p></div><button className="icon-button" aria-label="Dismiss error" onClick={() => setError('')}><X size={16} /></button></div>}
          {ingestMessage && <div className={`notice ${ingestMessage.toLowerCase().includes('failed') || ingestMessage.toLowerCase().includes('unable') ? 'notice-error' : 'notice-success'}`}><Check size={16} /><p>{ingestMessage}</p></div>}
          {loading && !summary ? <div className="loading-state"><LoaderCircle className="spin" size={22} /> Connecting to local telemetry store</div> : null}

          {view === 'overview' && summary && <>
            <div className="kpi-grid">
              <Kpi label="Network events" value={summary.total_events} icon={Activity} detail={`${summary.simulated_events} simulated`} accent="lime" />
              <Kpi label="Security alerts" value={summary.total_alerts} icon={Siren} detail="Persisted detections" accent="coral" />
              <Kpi label="Critical / high" value={summary.critical_alerts + summary.high_alerts} icon={AlertTriangle} detail={`${summary.critical_alerts} critical · ${summary.high_alerts} high`} accent="amber" />
              <Kpi label="Source addresses" value={summary.unique_source_ips} icon={Network} detail="Distinct observed" accent="cyan" />
              <Kpi label="Targeted hosts" value={summary.targeted_hosts} icon={ShieldCheck} detail="Distinct destinations" accent="blue" />
              <Kpi label="Destination ports" value={summary.unique_destination_ports} icon={Filter} detail="Distinct TCP / UDP ports" accent="lime" />
              <Kpi label="Active incidents" value={summary.active_incidents} icon={Siren} detail="Not resolved or closed" accent="amber" />
            </div>

            <div className="overview-grid">
              <section className="panel timeline-panel">
                <PanelHeading title="Event volume" eyebrow="OBSERVED TRAFFIC" aside={`${events.length} latest events`} />
                {timeline.length ? <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeline} margin={{ top: 10, right: 8, left: -20, bottom: 0 }}>
                    <defs><linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#b5e85d" stopOpacity={0.28} /><stop offset="100%" stopColor="#b5e85d" stopOpacity={0} /></linearGradient></defs>
                    <CartesianGrid stroke="#2c3029" strokeDasharray="3 5" vertical={false} />
                    <XAxis dataKey="label" tick={{ fill: '#858a7e', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis allowDecimals={false} tick={{ fill: '#858a7e', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: '#1b1e18', border: '1px solid #373b32', borderRadius: 5, color: '#edf0e6', fontSize: 12 }} />
                    <Area type="monotone" dataKey="events" name="Events" stroke="#b5e85d" strokeWidth={2} fill="url(#eventFill)" />
                  </AreaChart>
                </ResponsiveContainer></div> : <EmptyState title="No timeline data" detail="Generate a clearly labeled synthetic scenario or ingest a log file." />}
                <div className="chart-foot"><span><i className="legend-dot" /> Network events</span><span>5-minute buckets · latest records</span></div>
              </section>

              <section className="panel severity-panel">
                <PanelHeading title="Alert severity" eyebrow="DETECTION OUTPUT" aside="All time" />
                {summary.total_alerts ? <div className="severity-list">{['Critical', 'High', 'Medium', 'Low', 'Informational'].map((level) => {
                  const amount = summary.severity_distribution[level] ?? 0
                  const percent = summary.total_alerts ? amount / summary.total_alerts * 100 : 0
                  return <div className="severity-row" key={level}><span className={`severity-key severity-${level.toLowerCase()}`} /><span className="severity-name">{level}</span><div className="severity-track"><i className={`severity-fill severity-${level.toLowerCase()}`} style={{ width: `${percent}%` }} /></div><strong>{amount}</strong></div>
                })}</div> : <EmptyState title="No alerts yet" detail="Detection counters populate when scan evidence is present." />}
                <div className="severity-foot"><CircleHelp size={14} /> Single events are not classified as scans.</div>
              </section>

              <section className="panel alerts-panel">
                <PanelHeading title="Recent detections" eyebrow="INVESTIGATIONS" action={<button className="text-button" onClick={() => setView('alerts')}>View all <ArrowUpRight size={14} /></button>} />
                <AlertTable alerts={alerts.slice(0, 5)} onSelect={(alert) => void openAlert(alert)} />
              </section>

              <section className="panel sources-panel">
                <PanelHeading title="Top source addresses" eyebrow="EVENT ORIGIN" aside="Latest 500 records" />
                {topSources.length ? <div className="source-list">{topSources.map(([address, amount], index) => <div className="source-row" key={address}><span className="source-rank">0{index + 1}</span><span className="mono">{address}</span><span className="source-bar"><i style={{ width: `${Math.max(8, amount / topSources[0][1] * 100)}%` }} /></span><strong>{amount}</strong></div>)}</div> : <EmptyState title="No source addresses" detail="No events are stored yet." />}
                <div className="panel-footnote">Counts are derived from currently stored events.</div>
              </section>
            </div>
          </>}

          {view === 'events' && <section className="panel data-panel">
            <PanelHeading title="Normalized network events" eyebrow={`${events.length} LOADED RECORDS`} action={<button className="button button-subtle" onClick={exportEvents}><ArrowDownToLine size={15} /> Export CSV</button>} />
            <SearchFilter query={query} setQuery={setQuery} />
            <EventTable events={filteredEvents} />
          </section>}

          {view === 'alerts' && <section className="panel data-panel">
            <PanelHeading title="Detection queue" eyebrow={`${alerts.length} PERSISTED ALERTS`} action={<button className="button button-subtle" onClick={exportAlerts}><ArrowDownToLine size={15} /> Export CSV</button>} />
            <SearchFilter query={query} setQuery={setQuery} />
            <div className="filter-row"><label>Severity <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></label><span>{filteredAlerts.length} results</span></div>
            <AlertTable alerts={filteredAlerts} onSelect={(alert) => void openAlert(alert)} />
          </section>}

          {view === 'incidents' && <section className="panel data-panel">
            <PanelHeading title="Incident queue" eyebrow={`${incidents.length} PERSISTED INCIDENTS`} action={<a className="button button-subtle" href={`${API_BASE}/api/reports/summary.csv`}><ArrowDownToLine size={15} /> Export SOC summary</a>} />
            {canWrite && <label className="form-label">Resolution note (required to resolve)<input value={resolutionText} maxLength={4000} onChange={(event) => setResolutionText(event.target.value)} placeholder="Document investigation findings and disposition" /></label>}
            <div className="table-scroll"><table><thead><tr><th>INCIDENT</th><th>STATUS</th><th>ASSIGNED ANALYST</th><th>LINKED ALERTS</th><th>UPDATED</th><th>UPDATE STATUS</th></tr></thead><tbody>
              {incidents.map((incident) => <tr key={incident.incident_id}><td><strong className="table-primary">{incident.title}</strong><small className="table-secondary mono">{incident.incident_id}</small></td><td><span className="status-chip">{incident.status}</span></td><td><select disabled={!canWrite} aria-label={`Assign ${incident.title}`} value={incident.assigned_to ?? ''} onChange={(event) => void updateIncidentAssignee(incident.incident_id, event.target.value).catch((reason) => setIngestMessage(String(reason)))}><option value="">Unassigned</option>{analysts.map((analyst) => <option key={analyst.username} value={analyst.username}>{analyst.username}</option>)}</select></td><td>{incident.alert_ids.length}</td><td className="time-cell">{formatTime(incident.updated_at)}</td><td><select disabled={!canWrite} aria-label={`Update status for ${incident.title}`} value={incident.status} onChange={(event) => void updateIncidentStatus(incident.incident_id, event.target.value).catch((reason) => setIngestMessage(String(reason)))}>{['New', 'Investigating', 'Escalated', 'Resolved', 'Closed'].map((status) => <option key={status}>{status}</option>)}</select></td></tr>)}
            </tbody></table>{incidents.length === 0 && <EmptyState title="No incidents" detail="Create an incident from an alert after reviewing its evidence." />}</div>
          </section>}

          {view === 'analysts' && <section className="panel data-panel">
            <PanelHeading title="SOC team accounts" eyebrow={`${analysts.length} ACTIVE ASSIGNEES`} />
            {canManageTeam && <form className="ingestion-form" onSubmit={(event) => void addAnalyst(event)}>
              <label className="form-label">Username<input required pattern="[A-Za-z0-9_-]+" maxLength={64} value={newUsername} onChange={(event) => setNewUsername(event.target.value)} /></label>
              <label className="form-label">Temporary password<input required type="password" minLength={12} maxLength={1024} autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></label>
              <label className="form-label">Role<select value={newRole} onChange={(event) => setNewRole(event.target.value as 'soc_analyst' | 'read_only_viewer')}><option value="soc_analyst">SOC Analyst</option><option value="read_only_viewer">Read-only Viewer</option></select></label>
              <button className="button button-primary" type="submit" disabled={busyAction || !canManageTeam}>{busyAction ? <LoaderCircle className="spin" size={16} /> : <UsersRound size={16} />} Create account</button>
            </form>}
            <div className="table-scroll"><table><thead><tr><th>USERNAME</th><th>ROLE</th></tr></thead><tbody>{analysts.map((analyst) => <tr key={analyst.username}><td className="mono">{analyst.username}</td><td>{analyst.role.replaceAll('_', ' ')}</td></tr>)}</tbody></table>{analysts.length === 0 && <EmptyState title="No active analysts" detail="Create an SOC analyst account to enable assignment." />}</div>
          </section>}

          {view === 'ingestion' && <section className="ingestion-layout">
            <div className="panel ingestion-panel">
              <PanelHeading title="Offline log ingestion" eyebrow="LOCAL FILE PROCESSING" />
              <p className="ingestion-intro">Upload an existing text log to normalize records and run the local detection rules. Files are limited to 5 MiB. No live network capture is performed.</p>
              <form onSubmit={uploadLog} className="ingestion-form">
                <label className="form-label">Sensor format<select value={ingestFormat} onChange={(event) => { setIngestFormat(event.target.value); setIngestFile(null) }}><option value="zeek">Zeek conn.log</option><option value="suricata">Suricata eve.json</option><option value="firewall">UFW syslog</option><option value="pcap">Offline PCAP / PCAPNG</option></select></label>
                <label className="file-drop"><Upload size={23} /><strong>{ingestFile?.name ?? 'Choose a log file'}</strong><span>{ingestFormat === 'pcap' ? 'Ethernet/raw IPv4/IPv6 capture · up to 5 MiB' : 'UTF-8 text · up to 5 MiB'}</span><input type="file" accept={ingestFormat === 'pcap' ? '.pcap,.pcapng,.cap' : '.log,.json,.txt'} onChange={(event: ChangeEvent<HTMLInputElement>) => setIngestFile(event.target.files?.[0] ?? null)} /></label>
                <button className="button button-primary" type="submit" disabled={!canWrite || busyAction || !ingestFile}>{busyAction ? <LoaderCircle size={16} className="spin" /> : <FileUp size={16} />} Parse and ingest</button>
              </form>
            </div>
            <div className="panel ingestion-info"><div className="info-icon"><ShieldCheck size={20} /></div><h2>Supported sources</h2><ul><li><strong>Zeek</strong><span>TSV conn.log with #fields header</span></li><li><strong>Suricata</strong><span>JSON Lines EVE records</span></li><li><strong>Firewall</strong><span>UFW syslog with SRC/DST metadata</span></li><li><strong>PCAP</strong><span>Offline Ethernet/raw IPv4 and IPv6 captures</span></li></ul><div className="info-warning"><AlertTriangle size={15} /> Offline capture parsing only; 5 MiB and 20,000 packet limit. Malformed records are reported; valid records in the same file can still be ingested.</div></div>
          </section>}

          {summary && <footer className="page-footer"><span><span className="footer-dot" /> LOCAL DATA STORE</span><span>{summary.data_mode} · external SIEM connections are not configured</span></footer>}
        </div>
      </section>

      {selectedAlert && <div className="drawer-backdrop" onClick={() => setSelectedAlert(null)}><aside className="alert-drawer" onClick={(event) => event.stopPropagation()}><div className="drawer-heading"><div><span className="eyebrow">ALERT INVESTIGATION</span><h2>{selectedAlert.rule_name}</h2></div><button className="icon-button" aria-label="Close alert details" onClick={() => setSelectedAlert(null)}><X size={17} /></button></div><span className={severityClass(selectedAlert.severity)}>{selectedAlert.severity}</span><dl className="alert-details"><Detail label="Alert ID" value={selectedAlert.alert_id} mono /><Detail label="Rule ID" value={selectedAlert.rule_id} mono /><Detail label="Source" value={selectedAlert.source_ip} mono /><Detail label="Destination" value={selectedAlert.destination_ip} mono /><Detail label="Scan type" value={selectedAlert.scan_type.toUpperCase()} /><Detail label="Confidence" value={`${Math.round(selectedAlert.confidence * 100)}%`} /><Detail label="Events" value={String(selectedAlert.event_count)} /><Detail label="Ports" value={selectedAlert.unique_ports.join(', ')} mono /><Detail label="First seen" value={formatTime(selectedAlert.first_seen)} /><Detail label="Last seen" value={formatTime(selectedAlert.last_seen)} /></dl><div className="drawer-explanation"><strong>Detection explanation</strong><p>{selectedAlert.detection_reason}</p></div><div className="drawer-explanation"><strong>Investigation guidance</strong><ol><li>Confirm source ownership and whether scanning is authorized.</li><li>Review event timing, destinations, and connection outcomes.</li><li>Correlate with firewall and endpoint telemetry before escalation.</li></ol></div><div className="drawer-explanation"><strong>Supporting event evidence</strong><ul>{selectedEvidence.slice(0, 20).map((event) => <li className="mono" key={event.event_id}>{event.event_id} · {event.destination_ip}:{event.destination_port ?? '—'}</li>)}</ul>{selectedEvidence.length > 20 && <small>Showing 20 of {selectedEvidence.length} evidence events.</small>}</div><label className="form-label">Assign analyst<input disabled={!canWrite} value={assignedAnalyst} maxLength={120} onChange={(event) => setAssignedAnalyst(event.target.value)} placeholder="Analyst name" /></label><label className="form-label">Alert status<select disabled={!canWrite} value={selectedAlert.status} onChange={(event) => void updateAlertStatus(event.target.value).catch((reason) => setIngestMessage(String(reason)))}>{['New', 'Investigating', 'Escalated', 'Resolved', 'Closed', 'False Positive'].map((status) => <option key={status}>{status}</option>)}</select></label>{canWrite && <div className="heading-actions"><button className="button button-subtle" onClick={() => void updateAlertStatus(selectedAlert.status).catch((reason) => setIngestMessage(String(reason)))}>Save alert changes</button><button className="button button-primary" onClick={() => void createIncident().catch((reason) => setIngestMessage(String(reason)))}>Create incident</button></div>}<div className="drawer-evidence">Evidence references <span>{selectedEvidence.length} persisted event records</span></div></aside></div>}
    </main>
  )
}

function Kpi({ label, value, icon: Icon, detail, accent }: { label: string; value: number; icon: typeof Radar; detail: string; accent: string }) {
  return <section className={`kpi-card accent-${accent}`}><div className="kpi-top"><span>{label}</span><Icon size={17} strokeWidth={1.8} /></div><strong>{value.toLocaleString()}</strong><small>{detail}</small></section>
}

function PanelHeading({ title, eyebrow, aside, action }: { title: string; eyebrow: string; aside?: string; action?: React.ReactNode }) {
  return <div className="panel-heading"><div><span className="panel-eyebrow">{eyebrow}</span><h2>{title}</h2></div>{action ?? (aside && <span className="panel-aside">{aside}</span>)}</div>
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="empty-state"><span><Activity size={17} /></span><strong>{title}</strong><p>{detail}</p></div>
}

function SearchFilter({ query, setQuery }: { query: string; setQuery: (value: string) => void }) {
  return <div className="table-toolbar"><label className="search-box"><Search size={16} /><input placeholder="Search IP, port, rule..." value={query} onChange={(event) => setQuery(event.target.value)} /></label><span className="toolbar-caption"><Filter size={14} /> FILTERED LOCALLY</span></div>
}

function EventTable({ events }: { events: NetworkEvent[] }) {
  return <div className="table-scroll"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PORT</th><th>PROTO</th><th>FLAGS</th><th>SENSOR</th></tr></thead><tbody>{events.map((event) => <tr key={event.event_id}><td className="time-cell">{formatTime(event.timestamp)}</td><td className="mono">{event.source_ip}</td><td className="mono">{event.destination_ip}</td><td>{event.destination_port ?? '—'}</td><td><span className="protocol-chip">{event.protocol.toUpperCase()}</span></td><td className="muted-cell">{event.tcp_flags?.join(' ') || 'not reported'}</td><td>{event.sensor_type}</td></tr>)}</tbody></table>{events.length === 0 && <EmptyState title="No matching events" detail="Try another search or ingest a log file." />}</div>
}

function AlertTable({ alerts, onSelect }: { alerts: Alert[]; onSelect: (alert: Alert) => void }) {
  return <div className="table-scroll"><table><thead><tr><th>SEVERITY</th><th>DETECTION</th><th>SOURCE</th><th>DESTINATION</th><th>EVENTS</th><th>LAST SEEN</th><th>STATUS</th><th /></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.alert_id} className="click-row" tabIndex={0} role="button" aria-label={`Investigate ${alert.rule_name} from ${alert.source_ip}`} onClick={() => onSelect(alert)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(alert) } }}><td><span className={severityClass(alert.severity)}>{alert.severity}</span></td><td><strong className="table-primary">{alert.rule_name}</strong><small className="table-secondary">{alert.rule_id}</small></td><td className="mono">{alert.source_ip}</td><td className="mono">{alert.destination_ip}</td><td>{alert.event_count}</td><td className="time-cell">{formatTime(alert.last_seen)}</td><td><span className="status-chip">{alert.status}</span></td><td><ChevronRight size={15} className="row-chevron" /></td></tr>)}</tbody></table>{alerts.length === 0 && <EmptyState title="No detection alerts" detail="No scan pattern matched the configured minimum evidence threshold." />}</div>
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div><dt>{label}</dt><dd className={mono ? 'mono' : ''}>{value || '—'}</dd></div>
}