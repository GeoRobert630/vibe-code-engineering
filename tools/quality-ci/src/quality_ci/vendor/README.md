# Vendored accessibility engine

| File | Origin | Version | License |
|---|---|---|---|
| `axe.min.js` | npm package `axe-core` (Deque Systems, https://github.com/dequelabs/axe-core) | 4.10.3 | MPL-2.0 (`axe-core-LICENSE.txt`) |

`axe.min.js` is unmodified. Its SHA-256 is pinned in `quality_ci/engine.py` (`AXE_SHA256`) and verified before
every run, so the rules evaluated are fixed for a given release of this tool. To upgrade: `npm pack axe-core@<version>`,
copy `package/axe.min.js` and `package/LICENSE` here, and update `AXE_VERSION` / `AXE_SHA256`.
