"""pytest path bootstrap for the dns spoke test suite.

``dns_spoke`` imports its sibling ``unbound_manager`` as a bare name, so
``dns/src`` must be on ``sys.path``. It also inherits ``BaseSpoke`` from the LM
``core`` repo (``core.src.base_spoke`` / bare ``base_spoke``), so core's parent
dir must be on the path too — in dev that's the sibling ``lm`` repo
(``vscode/lm/core``), in prod ``/opt/lm/core`` alongside the dns checkout.
Mirrors the cs lm-spoke conftest.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("LM_DEP_GUARD_DISABLE", "1")

HERE = Path(__file__).resolve().parent        # dns/tests
DNS_REPO = HERE.parent                         # dns
SRC = DNS_REPO / "src"
for p in (str(SRC), str(DNS_REPO)):
    if p not in sys.path:
        sys.path.insert(0, p)

VSROOT = DNS_REPO.parent                       # .../vscode (dev)
# core.src.base_spoke (fallback import) needs core's parent on the path; bare
# base_spoke needs lm/core/src. Insert both candidates for dev + prod layouts.
for cand in (VSROOT / "lm" / "core", VSROOT / "core", DNS_REPO / "core"):
    if (cand / "src" / "base_spoke.py").is_file():
        core_parent = str(cand.parent)
        core_src = str(cand / "src")
        for cp in (core_parent, core_src):
            if cp not in sys.path:
                sys.path.insert(0, cp)
        break