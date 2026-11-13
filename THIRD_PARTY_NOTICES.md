# Third-party software

DFIR_VAO_Forensics is licensed under AGPL-3.0. This page covers software made by other people
that the project uses. All rights in that software stay with its authors.

## What this repository does NOT ship

- **No ready-made collector.** There is no prebuilt `DFIR_Collector.exe` with forensic tools inside it,
  either in this repository or in its releases.
- **The Collector Builder** (`DFIR_VAO_Collector_Builder_*.exe` in Releases) holds only our own code.
  When you run it, **your PC downloads each tool from its author's official address** (listed in
  [`src/collector_src/tools.json`](src/collector_src/tools.json)). Then it builds a collector for
  **your** server only. What was downloaded, from where and with which SHA-256 is written to
  `TOOLS_PROVENANCE.txt` next to the result.
- **KAPE** (Kroll) is not downloaded and not redistributed. Kroll's licence does not allow it.
  You get KAPE yourself from Kroll (free form) and point the builder at your copy. Using KAPE is
  subject to Kroll's licence terms, including the terms for commercial use.
- Each built collector carries **your own server key**. A collector built by someone else is useless
  to you, which is one more reason we never publish one.

## The only third-party files we host

The `tools-mirror` release contains tools whose original download links are gone, or whose
author dropped the .NET Framework build the collector needs (targets have no .NET runtime):

| File | Author | Licence |
|---|---|---|
| `SQLECmd.zip` | Eric Zimmerman | MIT |
| `WxTCmd.exe` | Eric Zimmerman | MIT |
| `AmcacheParser.zip` | Eric Zimmerman | MIT (last .NET Framework build; the root zip is 404 since 2026-10) |
| `ForensicTimeliner.zip` | acquiredsecurity | upstream repository removed |

A PRIVATE installation may also keep fallback copies of the other tools there
(`tools/collector_mirror_sync.py`): the builder uses one only when the author's link fails or fails
verification, and only if it matches the mirror's `SHA256SUMS`. Such a full mirror is never published.

These files are unchanged copies of the author's builds. Under the MIT licence they may be redistributed
with the copyright notice: *Copyright (c) Eric Zimmerman*. The software is provided "as is", without
warranty of any kind.

## Tools the builder downloads from their authors

Always the newest release. Each file is verified before it goes into the collector: GitHub's sha256
digest of the release asset, the author's Authenticode signature (EZ Tools: ZimTech LLC, Sysinternals:
Microsoft) or a pinned SHA-256; the version and the check used are written to `TOOLS_PROVENANCE.txt`.

| Tool | Author / source | Licence |
|---|---|---|
| AppCompatCacheParser, EvtxECmd, JLECmd, LECmd, MFTECmd, PECmd, RBCmd, RECmd, RecentFileCacheParser, SBECmd, SrumECmd, SumECmd, bstrings, rla | Eric Zimmerman, ericzimmermanstools.com | MIT |
| Hayabusa | Yamato Security, GitHub | AGPL-3.0 |
| Chainsaw | WithSecure Labs, GitHub | GPL-3.0 |
| DeepBlueCLI | Eric Conrad, GitHub | GPL-3.0 |
| RegRipper 3.0 | Harlan Carvey, GitHub | MIT |
| Hindsight | Obsidian Forensics, GitHub | Apache-2.0 |
| Autoruns | Microsoft Sysinternals | Sysinternals Software License Terms |
| Log Parser 2.2 | Microsoft | Microsoft software licence |
| Microsoft.Win32.Registry | Microsoft, NuGet | MIT |
| BrowserDownloadsView | NirSoft | Freeware (NirSoft terms) |
| 7-Zip (7za) | Igor Pavlov, 7-zip.org | GNU LGPL (+ unRAR restriction); `license.txt` is kept next to the binary |
| BrowserParser, reg_hunter, LevelDBDumper, LolDriverScan, forensicsim, BitsParser, mplog_parser, Defender DetectionHistory parser | their GitHub authors (links in `tools.json`) | see the licence in each author's repository |

ForensicTimeliner is left out of the builder because its licence does not allow redistribution.

## Software used on the server

Docker images are pulled from their official registries when you install. They are not part of this
repository. Each one keeps its own licence: PostgreSQL, n8n (Sustainable Use License), Open WebUI,
nginx, tusd, Qdrant, ngrok agent, pgAdmin, llama.cpp / llama-swap, and the language models you choose.

## Something wrong?

If you are an author and something here is incorrect, or you want your tool removed from the builder,
open an issue or use the contact in [SECURITY.md](SECURITY.md). We will fix it promptly.
