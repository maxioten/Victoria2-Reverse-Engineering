#!/usr/bin/env bash
# Source this file. Paths are project local; no global installation or shell startup edits.
v2_re_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export V2_RE_ROOT="$v2_re_root"
export JAVA_HOME="$v2_re_root/../tools/jdk/jdk-25.0.4.1+1"
export GHIDRA_INSTALL_DIR="$v2_re_root/../tools/ghidra/ghidra_12.1.4_PUBLIC"
export UV_CACHE_DIR="$v2_re_root/.cache/uv"
export XDG_CONFIG_HOME="$v2_re_root/projects/tool-config"
export XDG_CACHE_HOME="$v2_re_root/projects/tool-cache"
export PATH="$v2_re_root/.venv/bin:$JAVA_HOME/bin:$v2_re_root/../tools/rizin/bin:$v2_re_root/../tools/uv/uv-x86_64-unknown-linux-gnu:$PATH"
unset v2_re_root
