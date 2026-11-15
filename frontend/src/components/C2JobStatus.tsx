import { useTranslation } from 'react-i18next'
import { matchC2Job, type C2JobLike } from '../lib/c2'

export default function C2JobStatus({ url, jobs }: { url: string; jobs: C2JobLike[] }) {
  const { t } = useTranslation()
  if (!url) return null
  const job = matchC2Job(url, jobs)
  if (job) {
    return (
      <span className="c2-job live" title={`${job.Name}:${job.Port}`}>
        {t('c2job.live', { name: job.Name, port: job.Port })}
      </span>
    )
  }
  return <span className="c2-job missing">{t('c2job.missing')}</span>
}
