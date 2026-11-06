const test = require('node:test');
const assert = require('node:assert/strict');
const { relayUrl, localUrl, daemonEnvironment } = require('../policy.cjs');
test('desktop accepts HTTPS relay origins and rejects unsafe addresses', () => {
  assert.equal(relayUrl('https://relay.test/'), 'https://relay.test');
  assert.equal(relayUrl('https://relay.test:9443'), 'https://relay.test:9443');
  assert.equal(relayUrl('http://192.168.1.20:8443'),'http://192.168.1.20:8443');
  assert.equal(relayUrl('http://127.0.0.1:8443'),'http://127.0.0.1:8443');
  for (const value of ['http://relay.test', 'file:///etc/passwd', 'https://user:pass@relay.test', 'https://relay.test/api', 'https://relay.test/?token=x', 'https://relay.test/#x', 'invalid']) {
    assert.throws(() => relayUrl(value));
  }
});
test('navigation is restricted to the actual daemon origin', () => {
  assert.equal(localUrl('http://127.0.0.1:17421/bootstrap#secret', 'http://127.0.0.1:17421'), true);
  for (const value of ['http://127.0.0.1:17422', 'http://127.0.0.1.attacker.test:17421', 'https://127.0.0.1:17421', 'javascript:alert(1)', 'file:///x']) {
    assert.equal(localUrl(value, 'http://127.0.0.1:17421'), false);
  }
});
test('daemon environment excludes secrets and Node injection', () => {
  const environment = daemonEnvironment({ NODE_OPTIONS: '--require evil', NODE_PATH: 'evil', ADMIN_TOKEN: 'secret', DATABASE_URL: 'secret', SystemRoot: 'C:\\Windows' }, 'D:\\vault', 'https://relay.test');
  assert.equal(environment.NODE_OPTIONS, undefined);
  assert.equal(environment.NODE_PATH, undefined);
  assert.equal(environment.ADMIN_TOKEN, undefined);
  assert.equal(environment.DATABASE_URL, undefined);
  assert.equal(environment.SystemRoot, 'C:\\Windows');
  assert.equal(environment.PORT, '17421');
  assert.equal(environment.RELAY_URL, 'https://relay.test');
});
