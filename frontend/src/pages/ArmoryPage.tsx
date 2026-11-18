import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import type { ArmoryPackage } from '../lib/types'
import DataTable, { type Column } from '../components/common/DataTable'
import StatusBadge from '../components/common/StatusBadge'
import EmptyState from '../components/common/EmptyState'
import { useToast } from '../components/common/Toast'
import './pages.css'

export default function ArmoryPage() {
  const { t } = useTranslation()
  const toast = useToast()
  const [packages, setPackages] = useState<ArmoryPackage[]>([])
  const [source, setSource] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [kind, setKind] = useState<'all' | 'alias' | 'extension'>('all')
  const [installing, setInstalling] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const d = await api.armoryIndex()
      setPackages(d.packages || [])
      setSource(d.source || '')
      setError('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const rows = useMemo(() => {
    if (kind === 'all') return packages
    return packages.filter((p) => p.kind === kind)
  }, [packages, kind])

  const install = async (p: ArmoryPackage) => {
    setInstalling(p.command_name)
    try {
      const res = await api.armoryInstall(p.command_name)
      toast.push('success', t('armory.installed', { name: res.alias?.Name || p.name }))
    } catch (e) {
      toast.push('error', `${t('common.failed')}: ${(e as Error).message}`)
    } finally {
      setInstalling('')
    }
  }

  const columns: Column<ArmoryPackage>[] = [
    {
      key: 'name',
      label: t('armory.thName'),
      sortable: true,
      render: (p) => <span className="mono">{p.name}</span>,
    },
    {
      key: 'command_name',
      label: t('armory.thCommand'),
      sortable: true,
      render: (p) => <span className="mono">{p.command_name}</span>,
    },
    {
      key: 'kind',
      label: t('armory.thKind'),
      sortable: true,
      render: (p) => (
        <StatusBadge tone={p.kind === 'alias' ? 'blue' : 'orange'}>
          {p.kind === 'alias' ? t('armory.kindAlias') : t('armory.kindExtension')}
        </StatusBadge>
      ),
    },
    {
      key: 'repo_url',
      label: t('armory.thRepo'),
      render: (p) => (
        <a className="mono" href={p.repo_url} target="_blank" rel="noreferrer">
          {p.repo_url.replace(/^https?:\/\//, '')}
        </a>
      ),
    },
    {
      key: 'install',
      label: '',
      render: (p) =>
        p.kind === 'alias' ? (
          <button
            type="button"
            className="btn sm primary"
            disabled={installing === p.command_name}
            onClick={() => void install(p)}
          >
            {installing === p.command_name ? t('armory.installing') : t('armory.install')}
          </button>
        ) : (
          <span className="form-hint">{t('armory.extensionHint')}</span>
        ),
    },
  ]

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">{t('armory.title')}</div>
          <div className="page-sub">{t('armory.sub', { count: packages.length })}</div>
        </div>
        <div className="toolbar">
          <div className="seg">
            <button type="button" className={kind === 'all' ? 'active' : ''} onClick={() => setKind('all')}>
              {t('armory.filterAll')}
            </button>
            <button type="button" className={kind === 'alias' ? 'active' : ''} onClick={() => setKind('alias')}>
              {t('armory.filterAlias')}
            </button>
            <button type="button" className={kind === 'extension' ? 'active' : ''} onClick={() => setKind('extension')}>
              {t('armory.filterExt')}
            </button>
          </div>
          <button type="button" className="btn" onClick={() => void load()} disabled={loading}>
            {t('common.refresh')}
          </button>
        </div>
      </div>
      <div className="form-hint warn-hint">{t('armory.caveat')}</div>
      {source && (
        <div className="form-hint">
          {t('armory.source')}: <span className="mono">{source}</span> · <Link to="/aliases">{t('armory.openAliases')}</Link>
        </div>
      )}
      {error && <div className="error-banner">{error}</div>}
      {!loading && rows.length === 0 && !error ? (
        <EmptyState title={t('armory.empty')} subtitle={t('armory.emptySub')} />
      ) : (
        <div className="card card-flush">
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(p) => `${p.kind}:${p.command_name}:${p.repo_url}`}
            searchable
            searchPlaceholder={t('armory.search')}
            searchText={(p) => `${p.name} ${p.command_name} ${p.kind} ${p.repo_url}`}
            loading={loading}
            empty={t('armory.empty')}
          />
        </div>
      )}
    </div>
  )
}
