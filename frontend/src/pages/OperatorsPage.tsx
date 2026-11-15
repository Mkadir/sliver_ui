import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import type { OperatorPresence } from '../lib/types'
import DataTable, { type Column } from '../components/common/DataTable'
import StatusBadge from '../components/common/StatusBadge'
import EmptyState from '../components/common/EmptyState'
import './pages.css'

export default function OperatorsPage() {
  const { t } = useTranslation()
  const [operators, setOperators] = useState<OperatorPresence[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = async () => {
    try {
      const d = await api.getOperators()
      setOperators(d.operators || [])
      setError('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const timer = setInterval(load, 8000)
    return () => clearInterval(timer)
  }, [])

  const online = operators.filter((o) => o.online).length

  const columns: Column<OperatorPresence>[] = [
    {
      key: 'name',
      label: t('operators.thName'),
      sortable: true,
      render: (o) => <span className="mono">{o.name || '—'}</span>,
    },
    {
      key: 'online',
      label: t('operators.thStatus'),
      sortable: true,
      sortValue: (o) => (o.online ? 1 : 0),
      render: (o) => (
        <StatusBadge tone={o.online ? 'green' : 'gray'} dot>
          {o.online ? t('operators.online') : t('operators.offline')}
        </StatusBadge>
      ),
    },
  ]

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <div className="page-title">{t('operators.title')}</div>
          <div className="page-sub">{t('operators.sub', { count: operators.length, online })}</div>
        </div>
        <div className="toolbar">
          <button type="button" className="btn" onClick={() => void load()}>
            {t('common.refresh')}
          </button>
        </div>
      </div>
      {error && <div className="error-banner">{error}</div>}
      {!loading && operators.length === 0 && !error ? (
        <EmptyState title={t('operators.empty')} subtitle={t('operators.emptySub')} />
      ) : (
        <div className="card card-flush">
          <DataTable
            columns={columns}
            rows={operators}
            rowKey={(o) => o.name}
            searchable
            searchPlaceholder={t('operators.search')}
            searchText={(o) => o.name}
            loading={loading}
            empty={t('operators.empty')}
          />
        </div>
      )}
    </div>
  )
}
