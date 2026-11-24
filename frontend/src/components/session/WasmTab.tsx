import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../../lib/api'
import type { WasmExecResult } from '../../lib/types'

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result as string
      resolve(result.split(',')[1] || '')
    }
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

export default function WasmTab({
  id,
  kind = 'session',
}: {
  id: string
  kind?: 'session' | 'beacon'
}) {
  const { t } = useTranslation()
  const [names, setNames] = useState<string[]>([])
  const [name, setName] = useState('')
  const [wasmFile, setWasmFile] = useState<File | null>(null)
  const [args, setArgs] = useState('')
  const [memfsFiles, setMemfsFiles] = useState<File[]>([])
  const [skipReg, setSkipReg] = useState(false)
  const [pipe, setPipe] = useState(false)
  const [loot, setLoot] = useState(false)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [result, setResult] = useState<WasmExecResult | null>(null)

  const load = useCallback(async () => {
    try {
      const d = await api.wasmList(id, kind)
      setNames(d.names || [])
      if (d.async && d.task_id) {
        setMessage(t('wasm.beaconQueued', { id: d.task_id }))
      }
    } catch (e) {
      setError((e as Error).message)
    }
  }, [id, kind, t])

  useEffect(() => {
    load()
  }, [load])

  const onWasmFile = (file: File | null) => {
    setWasmFile(file)
    if (file && !name) setName(file.name)
  }

  const registerOnly = async () => {
    setError('')
    setMessage('')
    if (!wasmFile) {
      setError(t('wasm.file'))
      return
    }
    setRunning(true)
    try {
      const b64 = await fileToBase64(wasmFile)
      const res = await api.wasmRegister(id, name || wasmFile.name, b64, kind)
      setMessage(res.async ? t('wasm.beaconQueued', { id: res.task_id }) : t('wasm.registered', { name: res.name }))
      await load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setRunning(false)
    }
  }

  const exec = async () => {
    setError('')
    setMessage('')
    setResult(null)
    setRunning(true)
    try {
      const memfs: Record<string, string> = {}
      for (const f of memfsFiles) {
        memfs[f.name] = await fileToBase64(f)
      }
      let wasmB64: string | undefined
      if (!skipReg) {
        if (!wasmFile) {
          setError(t('wasm.file'))
          setRunning(false)
          return
        }
        wasmB64 = await fileToBase64(wasmFile)
      }
      const res = await api.wasmExec(
        id,
        {
          name: name || wasmFile?.name || '',
          args_line: args,
          wasm_b64: wasmB64,
          skip_registration: skipReg,
          memfs,
          pipe: kind === 'session' && pipe,
          loot,
        },
        kind,
      )
      setResult(res)
      if (res.async && res.task_id) setMessage(t('wasm.beaconQueued', { id: res.task_id }))
      if (res.loot_id) setMessage(t('wasm.lootSaved', { id: res.loot_id }))
      await load()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="card">
      <div className="card-title">{t('wasm.title')}</div>
      <p className="page-sub" style={{ marginBottom: 12 }}>
        {t('wasm.hint')}
      </p>
      <p className="form-hint">{t('wasm.pipeHint')}</p>

      <div className="pf-form">
        <div className="field">
          <label>{t('wasm.name')}</label>
          <input value={name} onChange={(e) => setName(e.target.value)} list="wasm-names" />
          <datalist id="wasm-names">
            {names.map((n) => (
              <option key={n} value={n} />
            ))}
          </datalist>
        </div>
        <div className="field">
          <label>{t('wasm.file')}</label>
          <input
            type="file"
            accept=".wasm,application/wasm"
            onChange={(e) => onWasmFile(e.target.files?.[0] || null)}
          />
        </div>
        <div className="field">
          <label>{t('wasm.args')}</label>
          <input value={args} onChange={(e) => setArgs(e.target.value)} />
        </div>
        <div className="field">
          <label>{t('wasm.memfs')}</label>
          <input type="file" multiple onChange={(e) => setMemfsFiles(Array.from(e.target.files || []))} />
        </div>
      </div>
      <p className="form-hint">{t('wasm.memfsHint')}</p>
      {memfsFiles.length > 0 && (
        <div className="wasm-memfs">
          {memfsFiles.map((f) => (
            <span key={f.name} className="op-tag">
              {f.name}
            </span>
          ))}
        </div>
      )}

      <div className="toolbar" style={{ marginTop: 12 }}>
        <label className="check">
          <input type="checkbox" checked={skipReg} onChange={(e) => setSkipReg(e.target.checked)} />
          {t('wasm.skipReg')}
        </label>
        {kind === 'session' && (
          <label className="check">
            <input type="checkbox" checked={pipe} onChange={(e) => setPipe(e.target.checked)} />
            {t('wasm.pipe')}
          </label>
        )}
        <label className="check">
          <input type="checkbox" checked={loot} onChange={(e) => setLoot(e.target.checked)} />
          {t('wasm.loot')}
        </label>
        <button type="button" className="btn" onClick={registerOnly} disabled={running}>
          {t('wasm.register')}
        </button>
        <button type="button" className="btn primary" onClick={exec} disabled={running}>
          {running ? t('wasm.running') : t('wasm.exec')}
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}
      {message && (
        <div className="error-banner" style={{ borderColor: 'var(--green)', color: 'var(--green)', background: 'var(--success-bg)' }}>
          {message}
        </div>
      )}
      {result?.warning && <p className="form-hint warn-hint">{result.warning}</p>}

      <div className="card-title" style={{ marginTop: 16 }}>
        {t('wasm.list')}
      </div>
      {names.length === 0 ? (
        <div className="empty">{t('wasm.empty')}</div>
      ) : (
        <ul className="mono">
          {names.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}

      {result && !result.async && (
        <div style={{ marginTop: 12 }}>
          <div className="form-hint">
            {t('wasm.exitCode')}: {result.exit_code}
          </div>
          {result.stdout && (
            <pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>
              {result.stdout}
            </pre>
          )}
          {result.stderr && (
            <pre className="mono" style={{ whiteSpace: 'pre-wrap', color: 'var(--red)' }}>
              {result.stderr}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}
