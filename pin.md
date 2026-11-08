# pin.md — Sapper-v2 source pin

## Commit, date and license

| Item | Fixed value |
|---|---|
| Upstream | https://github.com/N1nEmAn/sapper-v2 |
| Upstream commit | 697b30f77ebedf5e551a0595b3e883f9c25f9e73 |
| Upstream commit date (UTC) | 2026-11-07T01:20:40Z |
| Source | lib/sapper.py |
| Upstream Git blob SHA-1 | 5aa390332ed47becca1eb678365fc5cee71c79a1 |
| Upstream license | MIT |
| LICENSE Git blob SHA-1 | 1508447015a322f3a90b344c18533c55dd2bf1df |
| SECRA source | vendor/sapper_v2/sapper.py |
| SECRA adapter | app/sapper_integration.py |

## SHA clarification

The commit 248b2e04242bbd49c3d5cc1068d7d756c3e1cffe belongs to mfpm15/secra-skill-vapt (2026-11-08T09:45:20Z). It is the **SECRA baseline**, not an upstream sapper-v2 commit. The port is pinned to upstream 697b30f7... above.

## Reproducible verification

Run from the SECRA repository root:

    git hash-object vendor/sapper_v2/sapper.py
    # Expected: 5aa390332ed47becca1eb678365fc5cee71c79a1
    git hash-object vendor/sapper_v2/LICENSE
    # Expected: 1508447015a322f3a90b344c18533c55dd2bf1df

Compare directly with the upstream repository:

    git clone https://github.com/N1nEmAn/sapper-v2.git /tmp/secra-sapper-upstream
    git -C /tmp/secra-sapper-upstream checkout --detach 697b30f77ebedf5e551a0595b3e883f9c25f9e73
    git -C /tmp/secra-sapper-upstream rev-parse HEAD
    git -C /tmp/secra-sapper-upstream hash-object lib/sapper.py
    cmp vendor/sapper_v2/sapper.py /tmp/secra-sapper-upstream/lib/sapper.py
    # cmp exit code 0 = identical source bytes

To obtain a separate SHA-256 local fingerprint, run:

    sha256sum vendor/sapper_v2/sapper.py

The Git blob SHA-1 and license blob SHA-1 above are grounded in the pinned upstream Git tree. Preserve the MIT license and attribution in vendor/sapper_v2.

[ASUMSI] /tmp/secra-sapper-upstream is a free disposable directory. Reason: the developer machine filesystem layout is unknown.
