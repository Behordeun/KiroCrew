import { useCallback, useMemo, type ChangeEvent, type FocusEvent, type ReactElement, type RefObject } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useComposerPickers } from '../../chat-core/composer/pickers'
import { ComposerPickerMenus } from '../../chat-core/composer/PickerMenus'
import type { ComposerPickerSource } from '../../chat-core/composer/pickerSource'
import type { ComposerControl } from '../../components/composerControl'
import { usePickerSource } from '../../components/dashboardPickerSource'

/** What the edit field needs from its host to open the `$` skill menu: the
 *  chat slot, and the agent and project the composer scopes its skills by. */
export interface EditSkillPickerTarget {
  slotId: string
  agentName?: string
  project?: string
}

/** The handlers the picker puts on the edit field. */
export interface EditFieldBinding {
  onChange: (e: ChangeEvent<HTMLTextAreaElement>) => void
  onFocus?: () => void
  onBlur?: (e: FocusEvent<HTMLTextAreaElement>) => void
}

/**
 * The `$` skill menu on a message's Edit & Resend field, the same menu and
 * token the composer inserts.
 *
 * Only the skill menu is offered. An `@` pick stages an attachment that a
 * resend does not carry, and `/` and `./` complete text the edit endpoint
 * sends as a plain prompt, so their menus would promise what the resend does
 * not do. The source is cut down to the skills read, which is the one rule
 * (`offers`) that decides whether a menu opens.
 *
 * The field itself stays the host's: `renderField` draws it with the handlers
 * here, so the bubble's auto-sizing grid still holds the textarea directly.
 */
export default function EditSkillPicker({ target, value, onValueChange, textareaRef, anchorRef, renderField }: {
  target: EditSkillPickerTarget
  value: string
  onValueChange: (next: string) => void
  textareaRef: RefObject<HTMLTextAreaElement>
  anchorRef: RefObject<HTMLElement>
  renderField: (bind: EditFieldBinding) => ReactElement
}) {
  const base = usePickerSource()
  const source = useMemo<ComposerPickerSource>(
    () => ('skills' in base ? { scope: base.scope, skills: base.skills } : { scope: base.scope }),
    [base],
  )
  const queryClient = useQueryClient()
  const composerControl = useCallback((): ComposerControl | null => {
    const textarea = textareaRef.current
    if (!textarea) return null
    return {
      focus: () => textarea.focus(),
      getRootElement: () => textarea,
      getSelection: () => ({
        start: textarea.selectionStart ?? 0,
        end: textarea.selectionEnd ?? textarea.selectionStart ?? 0,
      }),
      setSelection: (start, end = start, options) => {
        const max = textarea.value.length
        textarea.setSelectionRange(Math.min(start, max), Math.min(end, max))
        if (options?.focus) textarea.focus()
      },
    }
  }, [textareaRef])
  const pickers = useComposerPickers({
    source,
    project: target.project,
    typedCommandMenus: true,
    value,
    onChange: onValueChange,
    composerControl,
    queryClient,
    slotId: target.slotId,
    agentName: target.agentName,
  })
  const { openPickersForText, prefetchSkills, closePickers } = pickers
  const onChange = useCallback((e: ChangeEvent<HTMLTextAreaElement>) => {
    const next = e.target.value
    onValueChange(next)
    openPickersForText(next, next.slice(0, e.target.selectionStart ?? next.length))
  }, [onValueChange, openPickersForText])
  // The open menu reads Enter and Escape off the whole document, so it closes
  // when focus moves to another control: Enter in the main composer then sends
  // that draft instead of picking into this one. A menu row never takes focus
  // (its mousedown is prevented), and the consent dialog a pick opens is
  // skipped, so picking still works.
  const onBlur = useCallback((e: FocusEvent<HTMLTextAreaElement>) => {
    const next = e.relatedTarget
    if (next instanceof Element && !next.closest('[role="dialog"], [role="alertdialog"]')) closePickers()
  }, [closePickers])
  return (
    <>
      {renderField({ onChange, onFocus: prefetchSkills, onBlur })}
      <ComposerPickerMenus
        pickers={pickers}
        value={value}
        onChange={onValueChange}
        composerAnchorRef={anchorRef}
        sendOnEnter="enter"
        project={target.project}
        agentName={target.agentName}
      />
    </>
  )
}
