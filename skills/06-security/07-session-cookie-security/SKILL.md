---
name: session-cookie-security
description: Audit web sessions, cookies, token handling and session lifecycle.
---

# Session & Cookie Security

Check:
- cryptographic session/token generation
- expiry
- refresh lifecycle
- logout invalidation
- fixation resistance
- privilege-change rotation
- HTTPS transport
- HttpOnly
- Secure
- SameSite
- appropriate cookie scope
- token exposure in browser storage

Do not recommend one cookie strategy blindly. Review the application's authentication architecture and cross-site requirements first.
