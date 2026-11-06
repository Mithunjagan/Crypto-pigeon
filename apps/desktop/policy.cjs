const { URL } = require('node:url');

function relayUrl(value) {
  const url = new URL(value);
  const local=['127.0.0.1','[::1]','localhost'].includes(url.hostname)||/^10\./.test(url.hostname)||/^192\.168\./.test(url.hostname)||/^172\.(?:1[6-9]|2\d|3[01])\./.test(url.hostname)||/^\[f[cd][a-f0-9]{2}:/i.test(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol==='http:'&&local)) || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('Enter an HTTPS relay address without a path, password, query, or fragment.');
  }
  return url.origin;
}

function localUrl(value, origin) {
  try { return new URL(value).origin === origin; } catch { return false; }
}

function daemonEnvironment(source, home, relay) {
  // Do not pass Node injection settings or relay administrator secrets to the daemon.
  const result = {};
  for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'LANG']) {
    if (source[key]) result[key] = source[key];
  }
  return { ...result, NODE_ENV: 'production', RELAY_URL: relayUrl(relay), CRYPTO_PIGEON_HOME: home, PORT: '17421' };
}

module.exports = { relayUrl, localUrl, daemonEnvironment };
