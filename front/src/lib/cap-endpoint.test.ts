import test from 'node:test'
import assert from 'node:assert/strict'

import { resolveCapEndpoint } from './cap-endpoint.ts'

test('resolveCapEndpoint prefers the build-time endpoint', () => {
  assert.equal(
    resolveCapEndpoint('https://build.example/key/', 'https://runtime.example/key/'),
    'https://build.example/key/'
  )
})

test('resolveCapEndpoint falls back to the runtime endpoint when the build-time one is blank', () => {
  assert.equal(
    resolveCapEndpoint('', ' https://runtime.example/key/ '),
    'https://runtime.example/key/'
  )
  assert.equal(
    resolveCapEndpoint(undefined, 'https://runtime.example/key/'),
    'https://runtime.example/key/'
  )
})

test('resolveCapEndpoint ignores unsubstituted config.json placeholders', () => {
  assert.equal(resolveCapEndpoint('', '${CAP_API_ENDPOINT}'), undefined)
})

test('resolveCapEndpoint returns undefined when nothing is configured', () => {
  assert.equal(resolveCapEndpoint('', ''), undefined)
  assert.equal(resolveCapEndpoint(undefined, undefined), undefined)
  assert.equal(resolveCapEndpoint('   ', null), undefined)
  assert.equal(resolveCapEndpoint(undefined, 42), undefined)
})
