# logsmith — ARCHIVED 🪦

> **This repository has been archived.**

The functionality previously in `logsmith` has been consolidated into **[clawkit](https://github.com/Luv-Goel/clawkit)** — the unified DevOps CLI toolkit.

## What Was This?

**Log forensics toolkit — pattern analysis, anomaly detection, timeline reconstruction**

## Why Archived?

Rather than maintaining a dozen tiny single-purpose Python packages, all CLI tooling now lives under the `clawkit` umbrella. This means:

- ✅ One install: `pip install clawkit`
- ✅ Unified CLI: `clawkit sift`, `clawkit dotenv`, `clawkit mark`, etc.
- ✅ Shared utilities and consistent interface
- ✅ Faster development, fewer dependencies to track

## Migration

```bash
# Before (old way)
pip install logsmith

# After (new way)  
pip install clawkit
clawkit logs --help
```

👉 **Head to [clawkit](https://github.com/Luv-Goel/clawkit)** for the active, maintained version.

---
*Archived on May 10, 2026 — functionality merged into clawkit*
