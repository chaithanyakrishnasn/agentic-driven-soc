'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { Shield } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { showToast } from '@/lib/toast'
import type { Ticket } from '@/types'
import {
  MetricCards, IncidentFeed, ThreatTimeline, AttackMap,
  SimulationPanel, ConnectionStatus, LiveEventsPanel, IncidentModal,
} from '@/components/dashboard'
import DatasetSelector from '@/components/dashboard/DatasetSelector'
import { useStore } from '@/lib/store'
import { getWsClient, useWebSocket } from '@/lib/websocket'
import { dashboardApi, incidentsApi, alertsApi, liveEventsApi, ingestionApi } from '@/lib/api'
import type { Incident, Alert } from '@/types'

export default function DashboardPage() {
  const pathname = usePathname()
  const {
    incidents, alerts, metrics,
    setIncidents, setAlerts, setMetrics,
    prependIncident, prependAlert,
    wsConnected, setWsConnected, setLastEventTime,
  } = useStore()

  const [loading, setLoading] = useState(true)
  const [liveEvents, setLiveEvents] = useState<{ sev: string; msg: string; ts: number }[]>([])
  const [selectedIncident, setSelectedIncident] = useState<Partial<Incident> | null>(null)
  const [now, setNow] = useState('')
  const [today, setToday] = useState('')
  const demoTriggered = useRef(false)

  // ── Clock ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    const update = () => {
      const d = new Date()
      setNow(d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }))
      setToday(d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' }))
    }
    update()
    const t = setInterval(update, 1000)
    return () => clearInterval(t)
  }, [])

  // ── Load initial data ──────────────────────────────────────────────────────
  useEffect(() => {
    const load = async () => {
      try {
        const [m, inc, alrt] = await Promise.allSettled([
          dashboardApi.getMetrics(),
          incidentsApi.list({ limit: 30 }),
          alertsApi.list({ limit: 20 }),
        ])
        if (m.status === 'fulfilled') setMetrics(m.value)
        if (inc.status === 'fulfilled') setIncidents(inc.value)
        if (alrt.status === 'fulfilled') setAlerts(alrt.value)

        const incidentCount = inc.status === 'fulfilled' ? inc.value.length : 0
        if (incidentCount === 0 && !demoTriggered.current) {
          setTimeout(async () => {
            if (!demoTriggered.current) {
              demoTriggered.current = true
              try { await ingestionApi.triggerDemo() } catch {}
            }
          }, 3000)
        }
      } finally {
        setLoading(false)
      }
    }
    load()
    const poll = setInterval(async () => {
      try { setMetrics(await dashboardApi.getMetrics()) } catch {}
    }, 10_000)
    return () => clearInterval(poll)
  }, [])

  // ── Live events polling ────────────────────────────────────────────────────
  useEffect(() => {
    const fetchLive = async () => {
      try {
        const events = await liveEventsApi.getRecent(50)
        if (events.length > 0) {
          setLiveEvents(events.map((e) => ({
            sev: (e.severity || 'medium').toUpperCase(),
            threat_type: e.threat_type,
            dest_ip: e.dest_ip,
            bytes_sent: (e.raw_log as any)?.bytes_sent,
            msg: `${e.threat_type?.replace(/_/g, ' ')} from ${e.source_ip || 'unknown'}`,
            ts: new Date(e.created_at).getTime(),
          })))
        }
      } catch {}
    }
    fetchLive()
    const interval = setInterval(fetchLive, 15_000)
    return () => clearInterval(interval)
  }, [])

  // ── WebSocket ──────────────────────────────────────────────────────────────
  useEffect(() => {
    const client = getWsClient()
    client.connect()
    const unsub = client.on('*', (msg: any) => { if (msg?.type !== 'ack') setWsConnected(true) })
    const t = setTimeout(() => setWsConnected(client.isConnected), 2000)
    return () => { unsub(); clearTimeout(t) }
  }, [])

  useWebSocket('new_incident', useCallback((data: unknown) => {
    prependIncident(data as Partial<Incident>)
    setLastEventTime(new Date().toISOString())
  }, []))

  useWebSocket('new_alert', useCallback((data: unknown) => {
    prependAlert(data as Partial<Alert>)
    setLastEventTime(new Date().toISOString())
  }, []))

  useWebSocket('live_event', useCallback((data: unknown) => {
    const d = data as any
    const sev = (d?.classification?.severity || 'medium').toUpperCase()
    const threat_type = d?.classification?.threat_type
    setLiveEvents((prev) => [{ 
      sev, 
      msg: `${(threat_type || 'event').replace(/_/g, ' ')} from ${d?.event?.source_ip || 'unknown'}`, 
      threat_type,
      dest_ip: d?.event?.dest_ip,
      bytes_sent: d?.event?.bytes_sent,
      ts: Date.now() 
    }, ...prev.slice(0, 49)])
    setLastEventTime(new Date().toISOString())
  }, []))

  useWebSocket('new_threat', useCallback((data: unknown) => {
    const d = data as any
    const sev = (d?.severity || 'medium').toUpperCase()
    const threat_type = d?.threat_type
    setLiveEvents((prev) => [{ 
      sev, 
      msg: `${(threat_type || 'event').replace(/_/g, ' ')} from ${d?.source_ip || 'unknown'}`, 
      threat_type,
      dest_ip: d?.dest_ip,
      bytes_sent: d?.bytes_sent,
      ts: Date.now() 
    }, ...prev.slice(0, 49)])
    setLastEventTime(new Date().toISOString())
  }, []))

  useWebSocket('ticket_created', useCallback((data: unknown) => {
    const t = data as Ticket
    showToast(`New ${t.severity} ticket — TICK-${String(t.ticket_number).padStart(4, '0')}`, 'warning')
  }, []))

  useWebSocket('sla_breach', useCallback((data: unknown) => {
    const t = data as Ticket
    showToast(`⚠ SLA BREACH: TICK-${String(t.ticket_number).padStart(4, '0')} (${t.severity}) — ${t.assigned_analyst_name || 'Unassigned'}`, 'error')
  }, []))

  useWebSocket('ticket_resolved', useCallback((data: unknown) => {
    const t = data as Ticket
    showToast(`✅ TICK-${String(t.ticket_number).padStart(4, '0')} resolved by ${t.assigned_analyst_name}`, 'success')
  }, []))

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      overflow: 'hidden',
      background: '#0a0e1a',
      padding: '6px',
      gap: '6px',
    }}>

      {/* ── ROW 1: Header ─────────────────────────────────────────────────── */}
      <header style={{
        flexShrink: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
        height: 50,
        background: '#0f1629',
        border: '1px solid #1e2d4a',
        borderRadius: '8px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 7,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'rgba(0,212,255,0.15)', border: '1px solid rgba(0,212,255,0.3)',
            }}>
              <Shield style={{ width: 14, height: 14, color: '#00d4ff' }} />
            </div>
            <div>
              <span style={{ fontWeight: 700, color: '#e8eaf0', fontSize: 14 }}>SentinelAI</span>
              <span style={{
                marginLeft: 7, fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                letterSpacing: '0.12em', padding: '2px 5px', borderRadius: 3,
                color: '#00d4ff', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)',
              }}>SOC</span>
            </div>
          </div>
          <nav style={{ display: 'flex', gap: 4 }}>
          {[
            { href: '/dashboard', label: 'SOC Dashboard' },
            { href: '/analysts',  label: 'Analysts' },
            { href: '/tickets',   label: 'Tickets' },
            { href: '/logs',      label: 'Logs' },
          ].map(({ href, label }) => (
            <Link key={href} href={href} style={{
              color: pathname === href ? '#00d4ff' : '#6b7a99',
              fontSize: 12, textDecoration: 'none', padding: '3px 9px', borderRadius: 5,
              background: pathname === href ? 'rgba(0,212,255,0.08)' : 'transparent',
              fontWeight: pathname === href ? 600 : 400,
            }}>{label}</Link>
          ))}
          </nav>

        </div>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <span style={{ fontFamily: 'monospace', fontSize: 17, fontWeight: 700, color: '#00d4ff' }}>{now}</span>
          <span style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.1em', color: '#6b7a99' }}>{today}</span>
        </div>

        <ConnectionStatus connected={wsConnected} />
      </header>

      {/* ── ROW 2: Metric Cards ────────────────────────────────────────────── */}
      <div style={{ flexShrink: 0 }}>
        <MetricCards metrics={metrics} wsConnected={wsConnected} />
      </div>

      {/* ── ROW 3: Three-column main content ──────────────────────────────── */}
      <div style={{
        flex: 1,
        display: 'grid',
        gridTemplateColumns: '20% 1fr 20%',
        gap: '6px',
        minHeight: 0,
        overflow: 'hidden',
      }}>

        {/* LEFT PANEL — Live Feed, full height */}
        <IncidentFeed
          incidents={incidents}
          onSelect={(inc) => setSelectedIncident(inc)}
        />

        {/* CENTER PANEL — Timeline top, Map + Events bottom */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '6px',
          minHeight: 0,
          overflow: 'hidden',
        }}>
          {/* Threat Activity Timeline — 200px */}
          <div style={{
            flexShrink: 0,
            height: '200px',
            background: '#0f1629',
            border: '1px solid #1e2d4a',
            borderRadius: '8px',
            overflow: 'hidden',
          }}>
            <ThreatTimeline />
          </div>

          {/* Attack Map + Live Events side by side */}
          <div style={{
            flex: 1,
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '6px',
            minHeight: 0,
            overflow: 'hidden',
          }}>
            <AttackMap incidents={incidents} />
            <LiveEventsPanel events={liveEvents} />
          </div>
        </div>

        {/* RIGHT PANEL — Dataset Selector + Simulation */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '6px',
          minHeight: 0,
          overflow: 'hidden',
        }}>
          <DatasetSelector />
          <div style={{ flex: 1, minHeight: 0, overflow: 'hidden' }}>
            <SimulationPanel />
          </div>
        </div>

      </div>

      {/* Modal overlay */}
      {selectedIncident && (
        <IncidentModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
        />
      )}

    </div>
  )
}
