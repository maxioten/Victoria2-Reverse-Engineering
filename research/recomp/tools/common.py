"""Shared paths for the pcrecomp reproduction scripts.

Everything is configurable with environment variables so the scripts do not
contain local absolute paths:

    V2_ROOT         repository root (default: three levels above this file)
    V2_WORK         local work directory (default: <root>/work)
    V2_BIN          local copy of v2game.exe (default: <root>/base-game/v2game.exe)
    V2_ANALYSIS     pcrecomp analysis directory (default: <work>/analysis)
    V2_GEN          generated C directory (default: <work>/src/recomp/gen)
    V2_BUILD        object output directory (default: <work>/build)
    V2_LOGS         log directory (default: <work>/logs)
    PCRECOMP_SRC    pcrecomp checkout (default: <root>/pcrecomp)
"""
import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get("V2_ROOT", Path(__file__).resolve().parents[3]))
WORK = Path(os.environ.get("V2_WORK", ROOT / "work"))
BIN = Path(os.environ.get("V2_BIN", ROOT / "base-game" / "v2game.exe"))
ANALYSIS = Path(os.environ.get("V2_ANALYSIS", WORK / "analysis"))
GEN = Path(os.environ.get("V2_GEN", WORK / "src" / "recomp" / "gen"))
BUILD = Path(os.environ.get("V2_BUILD", WORK / "build"))
LOGS = Path(os.environ.get("V2_LOGS", WORK / "logs"))
PCRECOMP = Path(os.environ.get("PCRECOMP_SRC", ROOT / "pcrecomp"))

# pcrecomp modules (tools.lift.lift32, tools.disasm.disasm32, ...)
for _p in (PCRECOMP, PCRECOMP / "tools", PCRECOMP / "tools" / "lift"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
