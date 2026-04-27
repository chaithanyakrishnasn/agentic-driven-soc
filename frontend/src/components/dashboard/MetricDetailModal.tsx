'use client'

import { useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertCircle, Zap, Activity, Info, CheckCircle } from 'lucide-react'
import { dashboardExtApi } from '@/lib/api'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

function BenchmarkSection() {
  const [benchmarks, setBenchmarks] = useState<any[]>([])

  useEffect(() => {
    fetch(`${BASE_URL}/api/v1/datasets/benchmarks/summary`)
      .then(r => r.ok ? r.json() : [])
      .then(setBenchmarks)
      .catch(() => {})
  }, [])

  if (benchmarks.length === 0) return null

  return (
    <div style={{
      background: '#141d35',
      border: '1px solid #1e2d4a',
      borderRadius: '8px',
      padding: '14px 16px',
    }}>
      <div style={{ color: '#00d4ff', fontSize: '12px', fontWeight: 600, marginBottom: '12px' }}>
        MODEL PERFORMANCE ON REAL DATASETS
      </div>
      {benchmarks.map(b => (
        <div key={b.dataset_id} style={{
          padding: '10px 12px',
          background: '#0a0e1a',
          borderRadius: '6px',
          marginBottom: '8px',
          display: 'flex',
          flexDirection: 'column',
          gap: '6px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: '#e8eaf0', fontWeight: 600, fontSize: '13px' }}>{b.name}</span>
            <span style={{ color: '#6b7a99', fontSize: '11px' }}>
              {b.samples.toLocaleString()} records
            </span>
          </div>
          {b.benchmark ? (
            <div style={{ display: 'flex', gap: '14px', fontSize: '11px', flexWrap: 'wrap' }}>
              <span style={{ color: '#6b7a99' }}>
                Accuracy <span style={{ color: '#00ff9d' }}>{(b.benchmark.accuracy * 100).toFixed(1)}%</span>
              </span>
              <span style={{ color: '#6b7a99' }}>
                Precision <span style={{ color: '#00d4ff' }}>{(b.benchmark.precision * 100).toFixed(1)}%</span>
              </span>
              <span style={{ color: '#6b7a99' }}>
                Recall <span style={{ color: '#ffb800' }}>{(b.benchmark.recall * 100).toFixed(1)}%</span>
              </span>
              <span style={{ color: '#6b7a99' }}>
                F1 <span style={{ color: '#ff3b6b' }}>{b.benchmark.f1_score.toFixed(3)}</span>
              </span>
            </div>
          ) : (
            <span style={{ color: '#6b7a99', fontSize: '11px', fontStyle: 'italic' }}>
              {b.cached ? 'Not yet benchmarked — call POST /datasets/{id}/train then /benchmark' : 'Dataset not downloaded'}
            </span>
          )}
        </div>
      ))}
    </div>
  )
}

interface Props {
  isOpen: boolean
  onClose: () => void
  metricType: 'events' | 'threats' | 'critical' | 'false_positive' | 'detection_rate' | 'confidence' | null
}

const renderBreakdownValue = (val: any): React.ReactNode => {
  if (Array.isArray(val)) {
    if (val.length === 0) return <span style={{ color: '#6b7a99' }}>None</span>
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, width: '100%' }}>
        {val.map((item, idx) => (
          <div key={idx} style={{ fontSize: 12, background: 'rgba(255,255,255,0.03)', padding: '6px 10px', borderRadius: 4 }}>
            {typeof item === 'object' && item !== null ? (
               <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
                 {Object.entries(item).map(([k, v]) => (
                   <span key={k}><span style={{color: '#6b7a99'}}>{k}:</span> {String(v)}</span>
                 ))}
               </div>
            ) : String(item)}
          </div>
        ))}
      </div>
    )
  }
  if (typeof val === 'object' && val !== null) {
    const entries = Object.entries(val)
    if (entries.length === 0) return <span style={{ color: '#6b7a99' }}>None</span>
    return (
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {entries.map(([k, v]) => (
          <div key={k} style={{ background: 'rgba(255,255,255,0.05)', padding: '2px 6px', borderRadius: 4, fontSize: 12 }}>
            <span style={{ color: '#6b7a99' }}>{k}:</span> {String(v)}
          </div>
        ))}
      </div>
    )
  }
  return <span>{String(val)}</span>
}

export function MetricDetailModal({ isOpen, onClose, metricType }: Props) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<any>(null)
  const previousMetricRef = useRef<Props['metricType']>(null)

  useEffect(() => {
    if (!isOpen) return

    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)

    return () => window.removeEventListener('keydown', h)
  }, [isOpen, onClose])

  useEffect(() => {
    if (!isOpen || !metricType) return
    if (data && metricType === previousMetricRef.current) return

    let cancelled = false

    const fetchData = async () => {
      try {
        setLoading(true)
        setError(null)
        setData(null)

        const res = await dashboardExtApi.getMetricDetails(metricType)
        if (!cancelled) {
          previousMetricRef.current = metricType
          setData(res)
        }
      } catch (err: any) {
        if (!cancelled) {
          setError(err?.message || 'Failed to load metric details')
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    fetchData()

    return () => {
      cancelled = true
    }
  }, [isOpen, metricType])

  return (
    <AnimatePresence>
      {isOpen && (
        <div
          onClick={onClose}
          style={{
            position: 'fixed', inset: 0,
            background: 'rgba(0,0,0,0.85)',
            backdropFilter: 'blur(4px)',
            zIndex: 1000,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            padding: '20px',
          }}
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.95, opacity: 0, y: 20 }}
            onClick={(e) => e.stopPropagation()}
            style={{
              background: '#0f1629',
              border: '1px solid #1e2d4a',
              borderRadius: '12px',
              width: '650px',
              maxWidth: '95vw',
              maxHeight: '85vh',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
              boxShadow: '0 20px 50px rgba(0,0,0,0.5)',
            }}
          >
            {/* Header */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '16px 20px',
              borderBottom: '1px solid #1e2d4a',
              background: '#0a0e1a',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  background: 'rgba(0, 212, 255, 0.15)',
                  padding: '8px', borderRadius: '8px',
                }}>
                  <Activity style={{ color: '#00d4ff', width: 20, height: 20 }} />
                </div>
                <div>
                  <div style={{ color: '#6b7a99', fontSize: 11, fontWeight: 700, letterSpacing: '0.05em' }}>METRIC DETAILS</div>
                  <div style={{ color: '#e8eaf0', fontSize: 16, fontWeight: 700 }}>
                    {data?.summary?.label || (metricType ? metricType.replace('_', ' ').toUpperCase() : 'Loading...')}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
                {data?.summary?.value !== undefined && (
                  <div style={{ color: '#00d4ff', fontSize: 24, fontWeight: 'bold', fontFamily: 'monospace' }}>
                    {data.summary.value}
                  </div>
                )}
                <button
                  onClick={onClose}
                  style={{
                    background: 'none', border: '1px solid #1e2d4a',
                    color: '#6b7a99', fontSize: 16,
                    cursor: 'pointer', padding: '4px 10px',
                    borderRadius: 6,
                  }}
                  onMouseOver={(e) => { e.currentTarget.style.color = '#e8eaf0'; e.currentTarget.style.borderColor = '#6b7a99' }}
                  onMouseOut={(e)  => { e.currentTarget.style.color = '#6b7a99'; e.currentTarget.style.borderColor = '#1e2d4a' }}
                >✕</button>
              </div>
            </div>

            {/* Body */}
            <div style={{
              flex: 1, overflowY: 'auto', padding: '20px',
              display: 'flex', flexDirection: 'column', gap: 16,
            }}>
              {loading ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '60px' }}>
                  <div style={{
                    width: 32, height: 32, border: '3px solid #1e2d4a', borderTopColor: '#00d4ff',
                    borderRadius: '50%', animation: 'spin 1s linear infinite'
                  }} />
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                </div>
              ) : error ? (
                <div style={{ color: '#ff3b6b', background: 'rgba(255,59,107,0.1)', padding: '16px', borderRadius: '8px', border: '1px solid rgba(255,59,107,0.3)', display: 'flex', alignItems: 'center', gap: 12 }}>
                  <AlertCircle style={{ flexShrink: 0 }} />
                  <div style={{ fontSize: 14 }}>{error}</div>
                </div>
              ) : data ? (
                <>
                  {/* Explanation */}
                  {data.explanation && (
                    <div style={{ background: '#141d35', border: '1px solid #1e2d4a', borderRadius: '8px', padding: '16px' }}>
                      <div style={{ color: '#00d4ff', fontSize: 12, fontWeight: 600, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Info style={{ width: 14, height: 14 }} /> EXPLANATION
                      </div>
                      <p style={{ color: '#e8eaf0', fontSize: 14, margin: 0, lineHeight: 1.6 }}>
                        {data.explanation}
                      </p>
                    </div>
                  )}

                  {/* Breakdown */}
                  {data.breakdown && Object.keys(data.breakdown).length > 0 && (
                    <div style={{ background: '#141d35', border: '1px solid #1e2d4a', borderRadius: '8px', padding: '16px' }}>
                      <div style={{ color: '#a78bfa', fontSize: 12, fontWeight: 600, marginBottom: 12 }}>
                        📊 DATA BREAKDOWN
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {Object.entries(data.breakdown).map(([key, val]) => (
                          <div key={key} style={{ 
                            display: 'flex', 
                            flexDirection: Array.isArray(val) || typeof val === 'object' ? 'column' : 'row',
                            justifyContent: Array.isArray(val) || typeof val === 'object' ? 'flex-start' : 'space-between',
                            alignItems: Array.isArray(val) || typeof val === 'object' ? 'flex-start' : 'center', 
                            background: '#0a0e1a', padding: '12px 14px', borderRadius: '6px', border: '1px solid #1e2d4a',
                            gap: 8
                          }}>
                            <span style={{ color: '#6b7a99', fontSize: 13, textTransform: 'capitalize', fontWeight: 600 }}>{key.replace(/_/g, ' ')}</span>
                            <div style={{ color: '#e8eaf0', fontSize: 14, fontFamily: 'monospace', fontWeight: 'bold', width: '100%' }}>
                              {renderBreakdownValue(val)}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Insights */}
                  {data.insights && data.insights.length > 0 && (
                    <div style={{ background: '#141d35', border: '1px solid #1e2d4a', borderRadius: '8px', padding: '16px' }}>
                      <div style={{ color: '#ffb800', fontSize: 12, fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Zap style={{ width: 14, height: 14 }} /> KEY INSIGHTS
                      </div>
                      <ul style={{ margin: 0, paddingLeft: '24px', color: '#e8eaf0', fontSize: 14, lineHeight: 1.6 }}>
                        {data.insights.map((insight: string, idx: number) => (
                          <li key={idx} style={{ marginBottom: 6 }}>{insight}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Recommended Actions */}
                  {data.recommended_actions && data.recommended_actions.length > 0 && (
                    <div style={{ background: 'rgba(0, 255, 157, 0.05)', border: '1px solid rgba(0, 255, 157, 0.2)', borderRadius: '8px', padding: '16px' }}>
                      <div style={{ color: '#00ff9d', fontSize: 12, fontWeight: 600, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <CheckCircle style={{ width: 14, height: 14 }} /> RECOMMENDED ACTIONS
                      </div>
                      <ul style={{ margin: 0, paddingLeft: '24px', color: '#e8eaf0', fontSize: 14, lineHeight: 1.6 }}>
                        {data.recommended_actions.map((action: string, idx: number) => (
                          <li key={idx} style={{ marginBottom: 6 }}>{action}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Real dataset benchmark results — shown for detection/confidence metrics */}
                  {(metricType === 'detection_rate' || metricType === 'confidence') && (
                    <BenchmarkSection />
                  )}
                </>
              ) : null}
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}
