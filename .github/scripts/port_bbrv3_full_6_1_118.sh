#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKDIR="${REPO_ROOT}/kernel_workspace"
COMMON_DIR="${WORKDIR}/common"
SRC_DIR="${WORKDIR}/bbrv3-src"
PATCH_FILE="${REPO_ROOT}/.github/patches/bbrv3/6.1.118/0001-bbrv3-full-port-compat.patch"
BBRV3_COMMIT="${BBRV3_COMMIT:-90210de4b779d40496dee0b89081780eeddf2a60}"

fatal() {
  echo "::error::$*"
  exit 1
}

[[ -d "${COMMON_DIR}" ]] || fatal "missing kernel source tree: ${COMMON_DIR}"
[[ -f "${PATCH_FILE}" ]] || fatal "missing compat patch: ${PATCH_FILE}"

echo "[BBRv3] fetching fixed upstream commit: ${BBRV3_COMMIT}"
rm -rf "${SRC_DIR}"
mkdir -p "${SRC_DIR}"

git -C "${SRC_DIR}" init -q
git -C "${SRC_DIR}" remote add origin https://github.com/google/bbr.git
git -C "${SRC_DIR}" fetch --depth=1 origin "${BBRV3_COMMIT}"
git -C "${SRC_DIR}" checkout --detach -q FETCH_HEAD

actual_commit="$(git -C "${SRC_DIR}" rev-parse HEAD)"
[[ "${actual_commit}" == "${BBRV3_COMMIT}" ]] || fatal "unexpected upstream commit: ${actual_commit}"

echo "[BBRv3] syncing upstream files"
for rel in net/ipv4/tcp_bbr.c include/uapi/linux/inet_diag.h; do
  [[ -f "${SRC_DIR}/${rel}" ]] || fatal "upstream file missing: ${rel}"
  [[ -f "${COMMON_DIR}/${rel}" ]] || fatal "target file missing: ${rel}"
  cp "${SRC_DIR}/${rel}" "${COMMON_DIR}/${rel}"
done

echo "[BBRv3] applying compat patch"
git -C "${COMMON_DIR}" apply --check "${PATCH_FILE}"
git -C "${COMMON_DIR}" apply "${PATCH_FILE}"

# Enforce CA private storage size required by BBRv3 on 6.1 vendor trees.
ICSK_H="${COMMON_DIR}/include/net/inet_connection_sock.h"
[[ -f "${ICSK_H}" ]] || fatal "missing ${ICSK_H}"
python3 - "${ICSK_H}" <<'PY'
from pathlib import Path
import re
import sys
p = Path(sys.argv[1])
s = p.read_text(encoding='utf-8')
target = "icsk_ca_priv[160 / sizeof(u64)]"
if target not in s:
    s2, n = re.subn(r'icsk_ca_priv\[[^\]]+\]', target, s, count=1)
    if n != 1:
        raise SystemExit("failed to rewrite icsk_ca_priv size")
    s = s2
    p.write_text(s, encoding='utf-8', newline='\n')
PY

# Ensure btf.h provides __bpf_kfunc attributes so kfunc symbols are retained.
BTF_H="${COMMON_DIR}/include/linux/btf.h"
[[ -f "${BTF_H}" ]] || fatal "missing ${BTF_H}"
python3 - "${BTF_H}" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text(encoding='utf-8')
if "#define __bpf_kfunc" not in s:
    anchor = "#include <uapi/linux/bpf.h>\n"
    if anchor not in s:
        raise SystemExit("anchor not found in btf.h")
    ins = (
        "\n"
        "#ifndef __bpf_kfunc\n"
        "#define __bpf_kfunc __attribute__((__used__)) __attribute__((noinline))\n"
        "#endif\n"
        "#ifndef __bpf_kfunc_start_defs\n"
        "#define __bpf_kfunc_start_defs()\n"
        "#endif\n"
        "#ifndef __bpf_kfunc_end_defs\n"
        "#define __bpf_kfunc_end_defs()\n"
        "#endif\n"
        "#ifndef __bpf_hook_start\n"
        "#define __bpf_hook_start() __bpf_kfunc_start_defs()\n"
        "#endif\n"
        "#ifndef __bpf_hook_end\n"
        "#define __bpf_hook_end() __bpf_kfunc_end_defs()\n"
        "#endif\n"
    )
    s = s.replace(anchor, anchor + ins, 1)
    p.write_text(s, encoding='utf-8', newline='\n')
PY

# Ensure btf_ids.h has kfunc aliases if upstream sources reference them.
BTF_IDS_H="${COMMON_DIR}/include/linux/btf_ids.h"
[[ -f "${BTF_IDS_H}" ]] || fatal "missing ${BTF_IDS_H}"
python3 - "${BTF_IDS_H}" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text(encoding='utf-8')
if "#define BTF_KFUNCS_START" not in s:
    anchor = "extern struct btf_id_set8 name;\n"
    idx = s.find(anchor)
    if idx < 0:
        raise SystemExit("anchor not found in btf_ids.h")
    idx += len(anchor)
    ins = (
        "\n"
        "#ifndef BTF_KFUNCS_START\n"
        "#define BTF_KFUNCS_START(name) BTF_SET8_START(name)\n"
        "#endif\n"
        "#ifndef BTF_KFUNCS_END\n"
        "#define BTF_KFUNCS_END(name) BTF_SET8_END(name)\n"
        "#endif\n"
    )
    s = s[:idx] + ins + s[idx:]
    p.write_text(s, encoding='utf-8', newline='\n')
PY

echo "[BBRv3] validating compat results"
[[ -f "${COMMON_DIR}/net/ipv4/tcp_bbr.c" ]] || fatal "missing patched tcp_bbr.c"
[[ -f "${ICSK_H}" ]] || fatal "missing inet_connection_sock.h"

grep -Eq 'icsk_ca_priv\[[[:space:]]*160[[:space:]]*/[[:space:]]*sizeof\(u64\)\]' "${ICSK_H}" || fatal "ICSK_CA_PRIV_SIZE enlargement missing"

grep -q 'inflight_hi' "${COMMON_DIR}/net/ipv4/tcp_bbr.c" || fatal "BBRv3 feature marker inflight_hi missing"
grep -q 'bw_probe_up_rounds' "${COMMON_DIR}/net/ipv4/tcp_bbr.c" || fatal "BBRv3 feature marker bw_probe_up_rounds missing"

grep -q '#define __bpf_kfunc' "${COMMON_DIR}/include/linux/btf.h" || fatal "__bpf_kfunc macro missing in btf.h"
grep -q '#define BTF_KFUNCS_START' "${COMMON_DIR}/include/linux/btf_ids.h" || fatal "BTF_KFUNCS_START alias missing in btf_ids.h"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "BBRV3_PATCHED=true"
    echo "BBRV3_SOURCE_COMMIT=${BBRV3_COMMIT}"
  } >> "${GITHUB_ENV}"
fi

echo "[BBRv3] full port prepared successfully (commit ${BBRV3_COMMIT})"
