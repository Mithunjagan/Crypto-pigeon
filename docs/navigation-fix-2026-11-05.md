# Android Back and transitions — 5 November 2026

Installed the updated standalone app on the connected vivo V2422
(`10BEAN0MX8001J4`). Existing vaults and their data were preserved.

Back first lets Android dismiss the keyboard, then closes the top sheet or menu,
then returns from a conversation to Chats. At the root it backgrounds the task
instead of finishing the activity and destroying its local vault service.
Android 13+ uses the platform Back dispatcher; earlier versions retain the
`onBackPressed` handler. The activity also reuses its existing top instance.

Sheets now stack in their opening order. A nested PIN sheet appears above
Settings, and Back/Escape closes only that sheet. Conversation transitions use
a 220 ms slide; sheets use a short slide/fade without the previous zoom. Existing
history bubbles do not animate in one by one. Refreshing message statuses no longer
repeatedly scrolls a reader to the bottom. Reduced-motion preferences are respected.

Verification:

- Four real-device instrumentation checks passed: sheet dismissal, vault-tab
  navigation, keyboard dismissal, and background/return preserving the activity,
  WebView and draft.
- On the actual unlocked Pigeon test vault, physical Back closed the nested PIN
  sheet, then Settings, and kept the same process, vault and public identity.
- Eight offline UI checks passed with normal motion and again with reduced
  motion, covering nested sheets, timer/chat Back, root delegation, draft
  preservation, scroll position during polling and mobile layout.
- Three Back-navigation unit checks, three vault-fragment regression checks,
  nine native JVM checks, the React production build and Android app/test assembly
  passed.

The browser checks used explicitly isolated UI fixtures. They are not messaging
or cryptographic acceptance results. The built-in browser preview failed to
navigate, so the UI regression harness ran in a separate headless browser with
a fresh test profile and real animation timing.

Evidence: `artifacts/navigation-20261105/` contains `native-back.log`,
`actual-vault-navigation.json`, `browser-normal.json`, `browser-reduced.json`,
and the actual phone screenshots `phone-chats-fixed.png` and
`phone-settings-fixed.png`. Earlier virtual-time browser attempts timed out
around exit animations; the final normal-time runs passed.

Reproduce:

```powershell
node --test scripts/back-navigation.test.mjs scripts/vault-fragments.test.mjs
npm run build --workspace=@crypto-pigeon/local-ui
node scripts/android-native-build.mjs --offline --tests --jvm-tests
# With the installed debug/test APKs on an authorized device:
adb -s SERIAL shell am instrument -w -r -e phase navigation app.cryptopigeon.nativeclient.debug.test/app.cryptopigeon.nativeclient.NativeCryptoInstrumentation
# UI fixtures only; start the preview in another terminal:
node scripts/navigation-preview.mjs
node scripts/run-navigation-browser-check.mjs
```
