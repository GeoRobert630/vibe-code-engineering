---
name: file-upload-storage
description: Secure file uploads, object storage, downloads and media processing.
---

# File Upload & Storage Security

Check:
- size limits
- allowed file types
- actual file/content validation where relevant
- filename normalization
- path traversal
- SVG/HTML handling
- storage permissions
- public/private visibility
- signed URLs
- ownership/tenant isolation
- processing pipelines

Do not trust client-supplied MIME types alone.

Private files must remain inaccessible to unauthorized users even if a URL or object ID is guessed.
