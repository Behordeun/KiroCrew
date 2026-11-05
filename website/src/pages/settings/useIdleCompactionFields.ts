/**
 * Settings ▸ Chat ▸ Advanced, Context card: the idle compaction switch
 * (`session.idle_compaction`) and its minimum context field
 * (`session.idle_compaction_min_context_pct`). `ChatPanel` renders both rows and
 * calls this once per render.
 *
 * The field follows the server until edited and saves on blur or Enter. The
 * server CLAMPS a minimum outside 40-90 instead of refusing it (a value below the
 * floor is a request for the cheapest setting), so the field sends what was typed,
 * then shows the value saved and says why it differs.
 */
import { useState, useRef, useEffect } from 'react'
import { useMutation, type QueryClient, type UseQueryResult } from '@tanstack/react-query'
import { api } from '../../api/client'
import { fmtPercent } from '../../i18n/format'
import { i18nT } from '../../i18n/t'
import { type ClampNotice, type KirocrewConfigShape, IDLE_COMPACTION_MIN_PCT_DEFAULT } from './chatPanelOptions'
import { setConfigPathValue, type useOptimisticConfigPaths } from './useOptimisticConfigPaths'

const TOGGLE_PATH = 'session.idle_compaction'
const MIN_PATH = 'session.idle_compaction_min_context_pct'
const CONFIG_KEY = ['kirocrewConfig']

/** A stored percentage (50 = 50%) in the app language's percent format. */
export const idleCompactionPct = (v: number) => fmtPercent(v / 100, { maximumFractionDigits: 2 })

export function useIdleCompactionFields({
  qc, setPathSaveError, clearOwnPathError, mcQ, overlay, onSaveFailure,
}: {
  qc: QueryClient
  setPathSaveError: (path: string, msg: string) => void
  clearOwnPathError: (path: string) => void
  mcQ: UseQueryResult<KirocrewConfigShape>
  overlay: ReturnType<typeof useOptimisticConfigPaths>
  /** Brings the panel's save-error banner into view: both rows sit below the fold. */
  onSaveFailure: () => void
}) {
  const serverOn = mcQ.data?.session?.idle_compaction ?? false
  // The shared overlay shows the value being saved at click time, and on
  // success writes it into the config cache, so a refetch that fails after a
  // save that worked cannot put the switch back on the old value.
  const idleToggleMut = useMutation({
    ...overlay.mutationOpts<boolean>({
      queryKey: CONFIG_KEY,
      mutationFn: (v: boolean) => api.patchConfig(TOGGLE_PATH, v),
      path: () => TOGGLE_PATH,
      displayValue: v => v,
      applyToCache: (cached, v) => setConfigPathValue(cached as KirocrewConfigShape, TOGGLE_PATH, v),
      onFailure: () => {
        setPathSaveError(TOGGLE_PATH, i18nT('pages.settings.chatPanel.failed_to_save_idle_compaction'))
        onSaveFailure()
      },
      onSupersede: clearOwnPathError,
    }),
    scope: { id: TOGGLE_PATH },
  })
  const idleCompactionOn = overlay.shown(TOGGLE_PATH, serverOn)

  // The config cache is shared and outlives this hook. A minimum save that
  // settles after an unmount (a tab switch and back) must not write the cache,
  // or it could overwrite a newer value that the remounted panel saved. The
  // refetch still runs, so the server's value lands either way.
  const mountedRef = useRef(true)
  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const [localIdleMinPct, setLocalIdleMinPct] = useState('')
  const [idleMinClampNotice, setIdleMinClampNotice] = useState('')
  // True only while the user holds a typed, unsaved value: an untouched field
  // follows every refetch, and a blur without an edit saves nothing.
  const idleMinEditedRef = useRef(false)
  const serverMinPct = mcQ.data?.session?.idle_compaction_min_context_pct ?? IDLE_COMPACTION_MIN_PCT_DEFAULT
  useEffect(() => {
    if (mcQ.isSuccess && !idleMinEditedRef.current) setLocalIdleMinPct(String(serverMinPct))
  }, [mcQ.isSuccess, serverMinPct])

  const idleMinPctMut = useMutation({
    mutationFn: (n: number) => api.patchConfig(MIN_PATH, n),
    onMutate: () => clearOwnPathError(MIN_PATH),
    onSuccess: (data: { clamp_notice?: ClampNotice } | undefined, n: number) => {
      const notice = data?.clamp_notice
      // The stored value goes into the cache first, so a failed refetch
      // leaves the field on what the server holds, not on the old value.
      const stored = notice ? notice.stored : n
      const cached = qc.getQueryData<KirocrewConfigShape>(CONFIG_KEY)
      if (mountedRef.current && cached !== undefined) {
        qc.setQueryData(CONFIG_KEY, setConfigPathValue(cached, MIN_PATH, stored))
      }
      if (notice) {
        setLocalIdleMinPct(String(notice.stored))
        setIdleMinClampNotice(i18nT('pages.settings.chatPanel.idle_compaction_min_context_clamped', {
          requested: idleCompactionPct(notice.requested),
          stored: idleCompactionPct(notice.stored),
          min: idleCompactionPct(notice.min),
          max: idleCompactionPct(notice.max),
        }))
      } else {
        setIdleMinClampNotice('')
      }
      return qc.invalidateQueries({ queryKey: CONFIG_KEY })
    },
    // Kept on screen and still marked edited, so the next blur retries it.
    onError: (_err, n) => {
      setPathSaveError(MIN_PATH, i18nT('pages.settings.chatPanel.failed_to_save_idle_compaction_min_context'))
      onSaveFailure()
      idleMinEditedRef.current = true
      setLocalIdleMinPct(String(n))
    },
  })
  const editIdleMinPct = (v: string) => {
    idleMinEditedRef.current = true
    setLocalIdleMinPct(v)
    setIdleMinClampNotice('')
  }
  const commitIdleMinPct = () => {
    if (!idleMinEditedRef.current) return
    idleMinEditedRef.current = false
    const n = Number(localIdleMinPct)
    if (localIdleMinPct.trim() === '' || !Number.isFinite(n)) {
      setLocalIdleMinPct(String(serverMinPct))
      return
    }
    if (n === serverMinPct) return
    idleMinPctMut.mutate(n)
  }

  return {
    idleCompactionOn, idleToggleMut, localIdleMinPct, editIdleMinPct, commitIdleMinPct,
    idleMinClampNotice, idleMinPctMut,
  }
}
