import test from 'node:test'
import assert from 'node:assert/strict'

import { captchaAlignToJustify, captchaTokenFromForm } from './captcha.ts'

test('captchaTokenFromForm returns the trimmed token when present', () => {
  const form = new FormData()
  form.append('captcha_token', '  tok-123  ')
  assert.equal(captchaTokenFromForm(form), 'tok-123')
})

test('captchaTokenFromForm returns undefined when the field is absent', () => {
  const form = new FormData()
  assert.equal(captchaTokenFromForm(form), undefined)
})

test('captchaTokenFromForm returns undefined when the field is blank', () => {
  const form = new FormData()
  form.append('captcha_token', '   ')
  assert.equal(captchaTokenFromForm(form), undefined)
})

test('captchaAlignToJustify maps known alignments', () => {
  assert.equal(captchaAlignToJustify('left'), 'flex-start')
  assert.equal(captchaAlignToJustify('center'), 'center')
  assert.equal(captchaAlignToJustify('right'), 'flex-end')
})

test('captchaAlignToJustify defaults to center for unknown/undefined', () => {
  assert.equal(captchaAlignToJustify(undefined), 'center')
  assert.equal(captchaAlignToJustify('weird'), 'center')
})
