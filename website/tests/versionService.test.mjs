import { test } from 'node:test';
import assert from 'node:assert/strict';
import { VersionService, DEFAULT_VERSION } from '../src/services/versionService.ts';

test('VersionService: Synchronous default fallback version', () => {
  const service = new VersionService();
  const info = service.getVersion();
  assert.equal(info.version, DEFAULT_VERSION);
  assert.equal(info.cleanVersion, DEFAULT_VERSION.replace(/^v/, ''));
});

test('VersionService: Subscription receives immediate and subsequent updates', () => {
  const service = new VersionService();
  const received = [];

  const unsubscribe = service.subscribe((info) => {
    received.push(info.version);
  });

  assert.equal(received.length, 1);
  assert.equal(received[0], DEFAULT_VERSION);

  unsubscribe();
});
