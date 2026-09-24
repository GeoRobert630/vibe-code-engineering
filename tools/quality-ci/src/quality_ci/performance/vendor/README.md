# Vendored performance measurement library

| File | Origin | Version | SHA-256 | License |
|---|---|---|---|---|
| `web-vitals.attribution.iife.js` | npm package `web-vitals` (Google Chrome team, https://github.com/GoogleChrome/web-vitals), file `dist/web-vitals.attribution.iife.js` | 6.2.2 | `3ae0ee544ae45c5cd1e19d934080eaf356461a5563718fa3cef1960d26768b4e` | Apache-2.0 (`web-vitals-LICENSE.txt`) |

The file is unmodified. It was obtained with `npm pack web-vitals@6.2.2` (the same process as the vendored axe-core).
The attribution build is used because it reports the LCP element as a selector (`attribution.target`); only
`onFCP`, `onLCP`, `onCLS` and `onTTFB` are called (no `onINP`).

`WEB_VITALS_SHA256` in `quality_ci/performance/engine.py` pins the hash and is verified before every run; a mismatch
makes the engine unavailable (run INCOMPLETE). `.gitattributes` marks the file `-text` so it is checked out
byte-for-byte on every platform. To upgrade: `npm pack web-vitals@<version>`, copy `package/dist/web-vitals.attribution.iife.js`
and `package/LICENSE` here, and update `WEB_VITALS_VERSION` / `WEB_VITALS_SHA256`.
