#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WORKDIR="${REPO_ROOT}/kernel_workspace"
COMMON_DIR="${WORKDIR}/common"
PATCH_DIR="${WORKDIR}/bbrv3-upstream-patches"
BBRV3_COMMIT="${BBRV3_COMMIT:-90210de4b779d40496dee0b89081780eeddf2a60}"

PATCH_COMMITS=(
  "bd456f283b66"
  "1a91bb7c3ebf"
  "c30f8e0b0480"
  "29c1c44646ae"
  "a627517bdfe0"
  "0e6b4413cb4a"
  "3679f3b8da5a"
  "500bcfec22c4"
  "f2078939d4a8"
  "88e09e2b7c84"
  "5093de531d14"
  "6642024274d7"
  "9163f4486be7"
  "4d2e56435d43"
  "a631934cbcd8"
  "3ee83ca004fa"
  "703f20a1052d"
  "9120f8037e8b"
  "cb31f3d02b1d"
  "88aff899355d"
  "795544cc00f0"
)

fatal() {
  echo "::error::$*"
  exit 1
}

[[ -d "${COMMON_DIR}" ]] || fatal "missing kernel source tree: ${COMMON_DIR}"
echo "[BBRv3] verifying fixed upstream anchor commit: ${BBRV3_COMMIT}"
v3_head_commit="$(git ls-remote https://github.com/google/bbr.git refs/heads/v3 | awk '{print $1}')"
[[ -n "${v3_head_commit}" ]] || fatal "unable to resolve upstream ref refs/heads/v3"
[[ "${v3_head_commit}" == "${BBRV3_COMMIT}" ]] || fatal "upstream refs/heads/v3 mismatch: expected ${BBRV3_COMMIT}, got ${v3_head_commit}"
anchor_patch_file="$(mktemp)"
curl -fsSL --retry 3 --retry-delay 2 "https://github.com/google/bbr/commit/${BBRV3_COMMIT}.patch" -o "${anchor_patch_file}"
anchor_from="$(sed -n 's/^From \([0-9a-f]\{40\}\).*/\1/p' "${anchor_patch_file}" | head -n1)"
rm -f "${anchor_patch_file}"
[[ "${anchor_from}" == "${BBRV3_COMMIT}" ]] || fatal "fixed upstream anchor patch header mismatch: ${anchor_from:-unset}"

prepare_common_repo_for_am() {
  local tracked_paths=(
    "Documentation/networking/ip-sysctl.rst"
    "include/linux/btf.h"
    "include/linux/btf_ids.h"
    "include/linux/tcp.h"
    "include/net/inet_connection_sock.h"
    "include/net/netns/ipv4.h"
    "include/net/tcp.h"
    "include/uapi/linux/inet_diag.h"
    "include/uapi/linux/rtnetlink.h"
    "include/uapi/linux/snmp.h"
    "include/uapi/linux/tcp.h"
    "net/ipv4/Kconfig"
    "net/ipv4/Makefile"
    "net/ipv4/bpf_tcp_ca.c"
    "net/ipv4/proc.c"
    "net/ipv4/sysctl_net_ipv4.c"
    "net/ipv4/tcp.c"
    "net/ipv4/tcp_bbr.c"
    "net/ipv4/tcp_dctcp.c"
    "net/ipv4/tcp_input.c"
    "net/ipv4/tcp_ipv4.c"
    "net/ipv4/tcp_minisocks.c"
    "net/ipv4/tcp_output.c"
    "net/ipv4/tcp_rate.c"
  )
  if [[ ! -d "${COMMON_DIR}/.git" ]]; then
    git -C "${COMMON_DIR}" init -q
  fi
  git -C "${COMMON_DIR}" config user.name "github-actions[bot]"
  git -C "${COMMON_DIR}" config user.email "41898282+github-actions[bot]@users.noreply.github.com"
  for rel in "${tracked_paths[@]}"; do
    if [[ -e "${COMMON_DIR}/${rel}" ]]; then
      git -C "${COMMON_DIR}" add -- "${rel}"
    fi
  done
  if git -C "${COMMON_DIR}" rev-parse --verify HEAD >/dev/null 2>&1; then
    :
  elif git -C "${COMMON_DIR}" diff --cached --quiet --exit-code; then
    fatal "failed to create baseline commit for git am (no staged baseline files)"
  else
    git -C "${COMMON_DIR}" commit -q -m "BBRv3 upstream full-port baseline"
  fi
}

prefetch_patch_ancestor_blobs() {
  local short_sha="$1"
  local patch_file="$2"
  local full_sha="$3"
  local parent_sha

  parent_sha="$(
    python3 - "${patch_file}" "${full_sha}" "${COMMON_DIR}" <<'PY'
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

patch_file = Path(sys.argv[1])
full_sha = sys.argv[2]
common_dir = sys.argv[3]

api_headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "bbrv3-full-port-script",
}
token = os.environ.get("GITHUB_TOKEN")
if token:
    api_headers["Authorization"] = f"Bearer {token}"

commit_url = f"https://api.github.com/repos/google/bbr/commits/{full_sha}"
req = urllib.request.Request(commit_url, headers=api_headers)
with urllib.request.urlopen(req) as resp:
    commit = json.load(resp)
parents = commit.get("parents") or []
if not parents:
    raise SystemExit(f"no parent commit found for {full_sha}")
parent_sha = parents[0]["sha"]

entries = []
current_old_path = None
for line in patch_file.read_text(encoding="utf-8", errors="replace").splitlines():
    if line.startswith("diff --git "):
        parts = line.split()
        if len(parts) >= 4 and parts[2].startswith("a/"):
            current_old_path = parts[2][2:]
        else:
            current_old_path = None
        continue
    if current_old_path and line.startswith("index "):
        m = re.match(r"index ([0-9a-f]+)\.\.([0-9a-f]+)(?: \d+)?$", line.strip())
        if m:
            old_abbrev = m.group(1)
            entries.append((current_old_path, old_abbrev))
        current_old_path = None

raw_headers = {"User-Agent": "bbrv3-full-port-script"}
for old_path, old_abbrev in entries:
    if set(old_abbrev) == {"0"}:
        continue
    quoted_path = urllib.parse.quote(old_path, safe="/")
    raw_url = f"https://raw.githubusercontent.com/google/bbr/{parent_sha}/{quoted_path}"
    raw_req = urllib.request.Request(raw_url, headers=raw_headers)
    with urllib.request.urlopen(raw_req) as resp:
        blob_data = resp.read()
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(blob_data)
        tmp_path = tmp.name
    try:
        full_blob = subprocess.check_output(
            ["git", "-C", common_dir, "hash-object", "-w", tmp_path],
            text=True,
        ).strip()
    finally:
        os.unlink(tmp_path)
    if not full_blob.startswith(old_abbrev):
        raise SystemExit(
            f"blob prefix mismatch for {old_path}: expected prefix {old_abbrev}, got {full_blob}"
        )

print(parent_sha)
PY
  )" || fatal "failed to prefetch upstream ancestor blobs for ${short_sha}"

  echo "[BBRv3] prepared 3-way ancestor blobs for ${short_sha} (parent ${parent_sha})"
}

resolve_known_commit_conflict() {
  local short_sha="$1"

  case "${short_sha}" in
    a627517bdfe0)
      echo "[BBRv3] resolving known 3-way conflict for ${short_sha} with upstream-equivalent edits"
      git -C "${COMMON_DIR}" checkout --ours -- include/net/tcp.h net/ipv4/tcp_rate.c
      python3 - "${COMMON_DIR}" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
tcp_h = root / "include/net/tcp.h"
tcp_rate = root / "net/ipv4/tcp_rate.c"

s = tcp_h.read_text(encoding="utf-8")
if "static inline u32 tcp_stamp32_us_delta(u32 t1, u32 t0)" not in s:
    anchor = (
        "static inline u32 tcp_stamp_us_delta(u64 t1, u64 t0)\n"
        "{\n"
        "\treturn max_t(s64, t1 - t0, 0);\n"
        "}\n"
    )
    insert = (
        anchor
        "\n"
        "static inline u32 tcp_stamp32_us_delta(u32 t1, u32 t0)\n"
        "{\n"
        "\treturn max_t(s32, t1 - t0, 0);\n"
        "}\n"
    )
    if anchor not in s:
        raise SystemExit("failed to locate tcp_stamp_us_delta() anchor in include/net/tcp.h")
    s = s.replace(anchor, insert, 1)

s_new = re.sub(r'(\s)u64(\s+first_tx_mstamp;)', r'\1u32\2', s, count=1)
if s_new == s:
    raise SystemExit("failed to rewrite first_tx_mstamp type in include/net/tcp.h")
s = s_new
s_new = re.sub(r'(\s)u64(\s+delivered_mstamp;)', r'\1u32\2', s, count=1)
if s_new == s:
    raise SystemExit("failed to rewrite delivered_mstamp type in include/net/tcp.h")
s = s_new
tcp_h.write_text(s, encoding="utf-8", newline="\n")

t = tcp_rate.read_text(encoding="utf-8")
if "tcp_stamp32_us_delta(tp->first_tx_mstamp," not in t:
    t_new = t.replace("tcp_stamp_us_delta(tp->first_tx_mstamp,", "tcp_stamp32_us_delta(tp->first_tx_mstamp,", 1)
    if t_new == t:
        raise SystemExit("failed to rewrite send-phase timestamp helper in net/ipv4/tcp_rate.c")
    t = t_new
if "tcp_stamp32_us_delta(tp->tcp_mstamp," not in t:
    t_new = t.replace("tcp_stamp_us_delta(tp->tcp_mstamp,", "tcp_stamp32_us_delta(tp->tcp_mstamp,", 1)
    if t_new == t:
        raise SystemExit("failed to rewrite ack-phase timestamp helper in net/ipv4/tcp_rate.c")
    t = t_new
tcp_rate.write_text(t, encoding="utf-8", newline="\n")
PY
      git -C "${COMMON_DIR}" add -- include/net/tcp.h net/ipv4/tcp_rate.c
      return 0
      ;;
  esac

  return 1
}

download_and_apply_commit_patch() {
  local short_sha="$1"
  local patch_file="${PATCH_DIR}/${short_sha}.patch"
  local patch_url="https://github.com/google/bbr/commit/${short_sha}.patch"
  local patch_from

  echo "[BBRv3] downloading upstream patch ${short_sha}"
  curl -fsSL --retry 3 --retry-delay 2 "${patch_url}" -o "${patch_file}"

  patch_from="$(sed -n 's/^From \([0-9a-f]\{40\}\).*/\1/p' "${patch_file}" | head -n1)"
  [[ -n "${patch_from}" ]] || fatal "patch ${short_sha} missing 'From <sha>' header"
  [[ "${patch_from}" == "${short_sha}"* ]] || fatal "patch ${short_sha} header mismatch: ${patch_from}"
  prefetch_patch_ancestor_blobs "${short_sha}" "${patch_file}" "${patch_from}"

  echo "[BBRv3] applying upstream patch ${short_sha}"
  if ! git -C "${COMMON_DIR}" am -3 "${patch_file}"; then
    if resolve_known_commit_conflict "${short_sha}" && git -C "${COMMON_DIR}" am --continue; then
      echo "[BBRv3] resolved and continued patch ${short_sha}"
      return 0
    fi
    git -C "${COMMON_DIR}" am --abort || true
    fatal "failed to apply upstream patch ${short_sha}"
  fi
}

backport_kfunc_macros() {
  local btf_h="${COMMON_DIR}/include/linux/btf.h"
  local btf_ids_h="${COMMON_DIR}/include/linux/btf_ids.h"

  [[ -f "${btf_h}" ]] || fatal "missing ${btf_h}"
  [[ -f "${btf_ids_h}" ]] || fatal "missing ${btf_ids_h}"

  python3 - "${btf_h}" "${btf_ids_h}" <<'PY'
from pathlib import Path
import re
import sys

btf_h = Path(sys.argv[1])
btf_ids_h = Path(sys.argv[2])

s = btf_h.read_text(encoding='utf-8')
marker = "/* BBRv3 kfunc compat for 6.1 trees */\n"
if marker not in s:
    anchor = "#include <uapi/linux/bpf.h>\n"
    if anchor not in s:
        raise SystemExit("failed to find uapi/linux/bpf.h include in btf.h")
    compat = (
        marker
        "#ifndef __retain\n"
        "#define __retain\n"
        "#endif\n"
        "#ifndef __bpf_kfunc\n"
        "#define __bpf_kfunc __used __retain noinline\n"
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
        "#endif\n\n"
    )
    s = s.replace(anchor, anchor + "\n" + compat, 1)
s = re.sub(r'^\s*#define\s+__bpf_kfunc[^\n]*$',
           '#define __bpf_kfunc __used __retain noinline',
           s, count=1, flags=re.MULTILINE)
btf_h.write_text(s, encoding='utf-8', newline='\n')

t = btf_ids_h.read_text(encoding='utf-8')
if "#define BTF_SET8_KFUNCS" not in t:
    struct_tail = "};\n\n#ifdef CONFIG_DEBUG_INFO_BTF\n"
    if struct_tail not in t:
        raise SystemExit("failed to find btf_id_set8 section boundary in btf_ids.h")
    t = t.replace(struct_tail, "};\n\n#define BTF_SET8_KFUNCS\t\t(1 << 0)\n\n#ifdef CONFIG_DEBUG_INFO_BTF\n", 1)

if "#define BTF_KFUNCS_START(name)" not in t:
    debug_anchor = "extern struct btf_id_set8 name;\n"
    idx = t.find(debug_anchor)
    if idx < 0:
        raise SystemExit("failed to find debug BTF_SET8_END anchor in btf_ids.h")
    idx += len(debug_anchor)
    debug_macros = (
        "\n#define BTF_KFUNCS_START(name)\t\t\t\t\\\n"
        "BTF_SET8_START(name)\n\n"
        "#define BTF_KFUNCS_END(name)\t\t\t\t\\\n"
        "BTF_SET8_END(name)\n"
    )
    t = t[:idx] + debug_macros + t[idx:]

if "static struct btf_id_set8 __maybe_unused name = { .flags = BTF_SET8_KFUNCS };" not in t:
    ndebug_anchor = "#define BTF_SET8_END(name)\n"
    idx = t.find(ndebug_anchor)
    if idx < 0:
        raise SystemExit("failed to find non-debug BTF_SET8_END anchor in btf_ids.h")
    idx += len(ndebug_anchor)
    ndebug_macros = (
        "#define BTF_KFUNCS_START(name) static struct btf_id_set8 __maybe_unused name = { .flags = BTF_SET8_KFUNCS };\n"
        "#define BTF_KFUNCS_END(name)\n"
    )
    t = t[:idx] + ndebug_macros + t[idx:]

btf_ids_h.write_text(t, encoding='utf-8', newline='\n')
PY
}

echo "[BBRv3] preparing transient git repo for upstream patch replay"
rm -rf "${PATCH_DIR}"
mkdir -p "${PATCH_DIR}"
prepare_common_repo_for_am

echo "[BBRv3] replaying upstream dependency chain (no compat fallback)"
for sha in "${PATCH_COMMITS[@]}"; do
  download_and_apply_commit_patch "${sha}"
done

echo "[BBRv3] applying kfunc macro compat backport for 6.1 toolchain"
backport_kfunc_macros

echo "[BBRv3] validating compat results"
TCP_BBR="${COMMON_DIR}/net/ipv4/tcp_bbr.c"
TCP_H="${COMMON_DIR}/include/net/tcp.h"
LINUX_TCP_H="${COMMON_DIR}/include/linux/tcp.h"
ICSK_H="${COMMON_DIR}/include/net/inet_connection_sock.h"
NETNS_IPV4_H="${COMMON_DIR}/include/net/netns/ipv4.h"
TCP_PLB_C="${COMMON_DIR}/net/ipv4/tcp_plb.c"
MAKEFILE_IPV4="${COMMON_DIR}/net/ipv4/Makefile"
RTA_H="${COMMON_DIR}/include/uapi/linux/rtnetlink.h"
TCP_UAPI_H="${COMMON_DIR}/include/uapi/linux/tcp.h"
INET_DIAG_H="${COMMON_DIR}/include/uapi/linux/inet_diag.h"
SNMP_UAPI_H="${COMMON_DIR}/include/uapi/linux/snmp.h"
BTF_H="${COMMON_DIR}/include/linux/btf.h"
BTF_IDS_H="${COMMON_DIR}/include/linux/btf_ids.h"

for file in "${TCP_BBR}" "${TCP_H}" "${LINUX_TCP_H}" "${ICSK_H}" "${NETNS_IPV4_H}" "${TCP_PLB_C}" "${MAKEFILE_IPV4}" "${RTA_H}" "${TCP_UAPI_H}" "${INET_DIAG_H}" "${SNMP_UAPI_H}" "${BTF_H}" "${BTF_IDS_H}"; do
  [[ -f "${file}" ]] || fatal "missing expected file after replay: ${file}"
done

grep -q 'READ_ONCE(net->ipv4.sysctl_tcp_plb_enabled)' "${TCP_BBR}" || fatal "missing PLB sysctl usage in tcp_bbr.c"
grep -q 'TCP_CONG_WANTS_CE_EVENTS' "${TCP_BBR}" || fatal "missing TCP_CONG_WANTS_CE_EVENTS in tcp_bbr.c"
grep -Eq '\.skb_marked_lost[[:space:]]*=' "${TCP_BBR}" || fatal "missing skb_marked_lost callback in tcp_bbr.c"
grep -Eq '\.tso_segs[[:space:]]*=' "${TCP_BBR}" || fatal "missing tso_segs callback in tcp_bbr.c"
grep -q 'BTF_KFUNCS_START(tcp_bbr_check_kfunc_ids)' "${TCP_BBR}" || fatal "missing BTF_KFUNCS_START in tcp_bbr.c"
grep -q 'rs->tx_in_flight' "${TCP_BBR}" || fatal "missing tx_in_flight usage in tcp_bbr.c"
grep -q 'rs->is_acking_tlp_retrans_seq' "${TCP_BBR}" || fatal "missing is_acking_tlp_retrans_seq usage in tcp_bbr.c"
grep -q 'tp->tlp_orig_data_app_limited' "${TCP_BBR}" || fatal "missing tlp_orig_data_app_limited usage in tcp_bbr.c"

grep -q 'u32 tx_in_flight;' "${TCP_H}" || fatal "missing rate_sample.tx_in_flight in include/net/tcp.h"
grep -q 'bool is_ece;' "${TCP_H}" || fatal "missing rate_sample.is_ece in include/net/tcp.h"
grep -q 'bool is_acking_tlp_retrans_seq;' "${TCP_H}" || fatal "missing rate_sample.is_acking_tlp_retrans_seq in include/net/tcp.h"
grep -q 'TCP_CONG_WANTS_CE_EVENTS' "${TCP_H}" || fatal "missing TCP_CONG_WANTS_CE_EVENTS in include/net/tcp.h"
grep -Eq 'void[[:space:]]+\(\*skb_marked_lost\)\(struct sock \*sk, const struct sk_buff \*skb\);' "${TCP_H}" || fatal "missing skb_marked_lost op in include/net/tcp.h"
grep -Eq 'void[[:space:]]+\(\*cong_control\)\(struct sock \*sk, u32 ack, int flag, const struct rate_sample \*rs\);' "${TCP_H}" || fatal "missing new cong_control signature in include/net/tcp.h"

grep -q 'tlp_orig_data_app_limited' "${LINUX_TCP_H}" || fatal "missing tcp_sock.tlp_orig_data_app_limited in include/linux/tcp.h"
grep -q 'fast_ack_mode' "${LINUX_TCP_H}" || fatal "missing tcp_sock.fast_ack_mode in include/linux/tcp.h"
grep -q 'ICSK_CA_PRIV_SIZE' "${ICSK_H}" || fatal "missing ICSK_CA_PRIV_SIZE in include/net/inet_connection_sock.h"
if grep -Eq '160[[:space:]]*/[[:space:]]*sizeof\(u64\)' "${ICSK_H}"; then
  fatal "compat fallback ICSK_CA_PRIV_SIZE=160 detected"
fi

grep -q 'sysctl_tcp_plb_enabled' "${NETNS_IPV4_H}" || fatal "missing PLB netns sysctls in include/net/netns/ipv4.h"
grep -Eq 'tcp_plb\.o' "${MAKEFILE_IPV4}" || fatal "missing tcp_plb.o in net/ipv4/Makefile"
grep -q 'tcp_plb_update_state' "${TCP_PLB_C}" || fatal "missing tcp_plb implementation"
grep -q 'RTAX_FEATURE_ECN_LOW' "${RTA_H}" || fatal "missing RTAX_FEATURE_ECN_LOW in rtnetlink uapi"
grep -q 'TCPI_OPT_ECN_LOW' "${TCP_UAPI_H}" || fatal "missing TCPI_OPT_ECN_LOW in tcp uapi"
grep -q 'bbr_inflight_hi' "${INET_DIAG_H}" || fatal "missing BBRv3 inet_diag fields"
grep -q 'LINUX_MIB_TCPPLBREHASH' "${SNMP_UAPI_H}" || fatal "missing PLB SNMP counter in uapi"

grep -q '#define __bpf_kfunc __used __retain noinline' "${BTF_H}" || fatal "missing __bpf_kfunc compat macro in btf.h"
grep -q '#define BTF_KFUNCS_START(name)' "${BTF_IDS_H}" || fatal "missing BTF_KFUNCS_START macro in btf_ids.h"

if grep -Eq 'bbr_main_compat|bbr_min_tso_segs_compat|bbr_rs_is_ece|bbr_rs_is_acking_tlp_retrans_seq|bbr_rs_lost|bbr_rs_tx_in_flight|bbr_tcp_skb_tx_in_flight_is_suspicious' "${TCP_BBR}"; then
  fatal "compat wrapper residue detected in tcp_bbr.c"
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "BBRV3_PATCHED=true"
    echo "BBRV3_PATCH_MODE=upstream_full"
    echo "BBRV3_SOURCE_COMMIT=${BBRV3_COMMIT}"
  } >> "${GITHUB_ENV}"
fi

echo "[BBRv3] full upstream-equivalent port prepared successfully (anchor ${BBRV3_COMMIT})"
