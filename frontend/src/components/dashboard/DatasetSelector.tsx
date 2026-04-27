'use client'
import { useEffect, useState } from 'react'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

type Mode = 'synthetic' | 'nsl_kdd' | 'unsw_nb15'

interface DatasetInfo {
  id: string
  name: string
  cached: boolean
  trained: boolean
  last_benchmark: any
}

interface ReplayStatus {
  running: boolean
  current_dataset: string | null
  events_replayed: number
  attacks_replayed: number
}

export default function DatasetSelector() {
  const [datasets, setDatasets] = useState<DatasetInfo[]>([])
  const [activeMode, setActiveMode] = useState<Mode>('synthetic')
  const [replayStatus, setReplayStatus] = useState<ReplayStatus>({
    running: false,
    current_dataset: null,
    events_replayed: 0,
    attacks_replayed: 0,
  })
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const fetchState = async () => {
      try {
        const [dsRes, statusRes] = await Promise.all([
          fetch(`${BASE_URL}/api/v1/datasets/`),
          fetch(`${BASE_URL}/api/v1/datasets/replay/status`),
        ])
        if (dsRes.ok) setDatasets(await dsRes.json())
        if (statusRes.ok) {
          const s: ReplayStatus = await statusRes.json()
          setReplayStatus(s)
          if (s.running && s.current_dataset) {
            setActiveMode(s.current_dataset as Mode)
          } else if (!s.running) {
            // only reset to synthetic if we were previously in replay mode
            setActiveMode(prev => (prev !== 'synthetic' && !s.running) ? 'synthetic' : prev)
          }
        }
      } catch {
        // backend not yet up — silently ignore
      }
    }
    fetchState()
    const interval = setInterval(fetchState, 5_000)
    return () => clearInterval(interval)
  }, [])

  const switchMode = async (mode: Mode) => {
    if (busy) return
    setBusy(true)
    try {
      if (mode === 'synthetic') {
        await fetch(`${BASE_URL}/api/v1/datasets/replay/stop`, { method: 'POST' })
        setActiveMode('synthetic')
        setReplayStatus(s => ({ ...s, running: false, current_dataset: null }))
      } else {
        const res = await fetch(
          `${BASE_URL}/api/v1/datasets/${mode}/replay/start?events_per_second=5&sample_size=1000`,
          { method: 'POST' },
        )
        if (res.ok) {
          setActiveMode(mode)
          setReplayStatus(s => ({ ...s, running: true, current_dataset: mode, events_replayed: 0, attacks_replayed: 0 }))
        }
      }
    } catch {
      // network error — no-op
    } finally {
      setBusy(false)
    }
  }

  const ds = (id: string) => datasets.find(d => d.id === id)

  const btnStyle = (id: Mode): React.CSSProperties => {
    const active  = activeMode === id
    const avail   = id === 'synthetic' || !!ds(id)?.cached
    return {
      background:    active ? 'rgba(0,212,255,0.15)' : '#141d35',
      border:        `1px solid ${active ? '#00d4ff' : '#1e2d4a'}`,
      color:         active ? '#00d4ff' : avail ? '#6b7a99' : '#3d4566',
      padding:       '8px 4px',
      borderRadius:  '6px',
      cursor:        busy ? 'wait' : avail ? 'pointer' : 'not-allowed',
      fontSize:      '11px',
      fontWeight:    600,
      display:       'flex',
      flexDirection: 'column' as const,
      alignItems:    'center',
      gap:           '2px',
      transition:    'all 0.15s ease',
      opacity:       avail ? 1 : 0.5,
    }
  }

  const activeBench = activeMode !== 'synthetic' ? ds(activeMode)?.last_benchmark : null

  return (
    <div style={{
      background:    '#0f1629',
      border:        '1px solid #1e2d4a',
      borderRadius:  '8px',
      padding:       '10px 12px',
      display:       'flex',
      flexDirection: 'column',
      gap:           '8px',
      flexShrink:    0,
    }}>
      {/* Label row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ color: '#6b7a99', fontSize: '10px', fontWeight: 700, letterSpacing: '0.07em' }}>
          DATA SOURCE
        </span>
        {replayStatus.running && (
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#00ff9d', fontSize: '10px' }}>
            <span style={{
              width: '6px', height: '6px', borderRadius: '50%', background: '#00ff9d',
              boxShadow: '0 0 4px #00ff9d', animation: 'pulse 2s infinite',
            }} />
            {replayStatus.events_replayed} events · {replayStatus.attacks_replayed} attacks
          </span>
        )}
      </div>

      {/* Mode buttons */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '5px' }}>
        <button style={btnStyle('synthetic')} onClick={() => switchMode('synthetic')} disabled={busy}>
          <span>SYNTHETIC</span>
          <span style={{ fontSize: '9px', fontWeight: 400, opacity: 0.7 }}>Generated</span>
        </button>

        <button style={btnStyle('nsl_kdd')} onClick={() => switchMode('nsl_kdd')} disabled={busy || !ds('nsl_kdd')?.cached}>
          <span>NSL-KDD</span>
          <span style={{ fontSize: '9px', fontWeight: 400, opacity: 0.7 }}>
            {ds('nsl_kdd')?.cached ? 'Real · 125k' : 'Not cached'}
          </span>
        </button>

        <button style={btnStyle('unsw_nb15')} onClick={() => switchMode('unsw_nb15')} disabled={busy || !ds('unsw_nb15')?.cached}>
          <span>UNSW-NB15</span>
          <span style={{ fontSize: '9px', fontWeight: 400, opacity: 0.7 }}>
            {ds('unsw_nb15')?.cached ? 'Real · 175k' : 'Not cached'}
          </span>
        </button>
      </div>

      {/* Live benchmark mini-bar when a real dataset is active */}
      {activeBench && (
        <div style={{
          background:    '#0a0e1a',
          borderRadius:  '4px',
          padding:       '5px 9px',
          display:       'flex',
          gap:           '10px',
          fontSize:      '10px',
          color:         '#6b7a99',
          flexWrap:      'wrap',
        }}>
          <span>Acc <span style={{ color: '#00ff9d' }}>{(activeBench.accuracy * 100).toFixed(1)}%</span></span>
          <span>F1 <span style={{ color: '#00d4ff' }}>{activeBench.f1_score.toFixed(3)}</span></span>
          <span>Recall <span style={{ color: '#ffb800' }}>{(activeBench.recall * 100).toFixed(1)}%</span></span>
        </div>
      )}

      <style>{`
        @keyframes pulse {
          0%,100% { opacity:1; }
          50%      { opacity:0.4; }
        }
      `}</style>
    </div>
  )
}
