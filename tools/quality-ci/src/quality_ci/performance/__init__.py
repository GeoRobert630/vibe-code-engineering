"""Quality CI Phase 4B: performance (lab measurement).

Deterministic budget checks (bytes, request counts, render-blocking resources, DOM size, modelled critical path)
and lab timing checks (FCP, LCP, CLS, TBT) measured in headless Chromium under a fixed emulation profile, as the
median of several cold runs. Findings use the ``Q-PERF-*`` namespace; they are quality findings, never security
or accessibility findings. Lab data only: not field data and not proof of real-user performance.
"""

__version__ = "0.1.0"
TOOL_NAME = "quality-ci performance"
