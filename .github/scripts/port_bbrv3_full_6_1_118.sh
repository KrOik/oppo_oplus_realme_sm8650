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

TCP_BBR="${COMMON_DIR}/net/ipv4/tcp_bbr.c"
[[ -f "${TCP_BBR}" ]] || fatal "missing ${TCP_BBR}"
python3 - "${TCP_BBR}" <<'PY'
from pathlib import Path
import sys

p = Path(sys.argv[1])
s = p.read_text(encoding='utf-8')

if "BBRv3 compat for older 6.1 vendor trees" not in s:
    anchor = '#include "tcp_dctcp.h"\n'
    if anchor not in s:
        raise SystemExit("anchor include not found in tcp_bbr.c")
    compat_block = (
        "/* BBRv3 compat for older 6.1 vendor trees (no PLB/BPF kfunc/TLP event). */\n"
        "#ifndef __bpf_kfunc\n"
        "#define __bpf_kfunc\n"
        "#endif\n"
        "#ifndef TCP_ECN_LOW\n"
        "#define TCP_ECN_LOW 0\n"
        "#endif\n"
        "#ifndef TCP_ECN_ECT_PERMANENT\n"
        "#define TCP_ECN_ECT_PERMANENT 0\n"
        "#endif\n"
        "#ifndef CA_EVENT_TLP_RECOVERY\n"
        "#define CA_EVENT_TLP_RECOVERY ((enum tcp_ca_event)-1)\n"
        "#endif\n"
        "#ifndef TCP_PLB_SCALE\n"
        "#define TCP_PLB_SCALE BBR_SCALE\n"
        "struct tcp_plb_state {\n"
        "\tu32 pause_until;\n"
        "};\n"
        "static inline void tcp_plb_update_state(struct sock *sk, struct tcp_plb_state *plb, int ce_ratio) { }\n"
        "static inline void tcp_plb_check_rehash(struct sock *sk, struct tcp_plb_state *plb) { }\n"
        "static inline void tcp_plb_update_state_upon_rto(struct sock *sk, struct tcp_plb_state *plb) { }\n"
        "#endif\n"
        "\n"
        "/* 6.1 vendor compat helpers for rate_sample/tcp_skb_cb API differences. */\n"
        "static inline u32 bbr_rs_tx_in_flight(const struct rate_sample *rs) { return rs->prior_in_flight; }\n"
        "static inline s32 bbr_rs_lost(const struct rate_sample *rs) { return rs->losses; }\n"
        "static inline bool bbr_rs_is_ece(const struct rate_sample *rs) { return false; }\n"
        "static inline bool bbr_rs_is_acking_tlp_retrans_seq(const struct rate_sample *rs) { return false; }\n"
        "static inline bool bbr_tcp_skb_tx_in_flight_is_suspicious(u32 skb_pcount, u8 skb_sacked_flags, u32 tx_in_flight) { return false; }\n"
    )
    s = s.replace(anchor, anchor + "\n" + compat_block + "\n", 1)

replacements = [
    ("struct net *net = sock_net(sk);", "struct net *net __maybe_unused = sock_net(sk);"),
    ("READ_ONCE(net->ipv4.sysctl_tcp_plb_enabled)", "0"),
    ("rs->tx_in_flight", "bbr_rs_tx_in_flight(rs)"),
    ("rs->lost", "bbr_rs_lost(rs)"),
    ("rs->is_ece", "bbr_rs_is_ece(rs)"),
    ("rs->is_acking_tlp_retrans_seq", "bbr_rs_is_acking_tlp_retrans_seq(rs)"),
    ("rs.tx_in_flight", "rs.prior_in_flight"),
    ("rs.lost", "rs.losses"),
    ("TCP_SKB_CB(skb)->tx.lost", "0"),
    ("scb->tx.in_flight", "bbr->inflight_latest"),
    ("scb->tx.lost", "0"),
    ("tp->tlp_orig_data_app_limited", "0"),
    ("tp->fast_ack_mode = bbr_fast_ack_mode ? 1 : 0;", "(void)bbr_fast_ack_mode;"),
]
for old, new in replacements:
    s = s.replace(old, new)

s = s.replace("bbr_tcp_skb_tx_in_flight_is_suspicious(", "__BBR_TMP_TXINF__(")
s = s.replace("tcp_skb_tx_in_flight_is_suspicious(", "bbr_tcp_skb_tx_in_flight_is_suspicious(")
s = s.replace("__BBR_TMP_TXINF__(", "bbr_tcp_skb_tx_in_flight_is_suspicious(")
s = s.replace("| TCP_CONG_WANTS_CE_EVENTS", "")
s = s.replace(".tso_segs\t\t= bbr_tso_segs,", ".min_tso_segs\t= bbr_min_tso_segs_compat,")
s = s.replace(".tso_segs\t= bbr_tso_segs,", ".min_tso_segs\t= bbr_min_tso_segs_compat,")
s = s.replace(".tso_segs = bbr_tso_segs,", ".min_tso_segs\t= bbr_min_tso_segs_compat,")
s = s.replace(".min_tso_segs\t= bbr_tso_segs,", ".min_tso_segs\t= bbr_min_tso_segs_compat,")
s = s.replace(".min_tso_segs = bbr_tso_segs,", ".min_tso_segs\t= bbr_min_tso_segs_compat,")
s = s.replace(".cong_control\t= bbr_main,", ".cong_control\t= bbr_main_compat,")
s = s.replace(".cong_control = bbr_main,", ".cong_control\t= bbr_main_compat,")
s = s.replace("BTF_KFUNCS_START(", "BTF_SET8_START(")
s = s.replace("BTF_KFUNCS_END(", "BTF_SET8_END(")
s = "\n".join(line for line in s.splitlines() if ".skb_marked_lost" not in line) + "\n"

needle = "static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {"
if "static u32 bbr_min_tso_segs_compat(struct sock *sk)" not in s:
    if needle not in s:
        raise SystemExit("tcp_bbr_cong_ops marker not found")
    wrapper = (
        "static u32 bbr_min_tso_segs_compat(struct sock *sk)\n"
        "{\n"
        "\treturn bbr_tso_segs(sk, tcp_sk(sk)->mss_cache);\n"
        "}\n\n"
        "static void bbr_main_compat(struct sock *sk, const struct rate_sample *rs)\n"
        "{\n"
        "\tbbr_main(sk, 0, 0, rs);\n"
        "}\n\n"
    )
    s = s.replace(needle, wrapper + needle, 1)
elif "static void bbr_main_compat(struct sock *sk, const struct rate_sample *rs)" not in s:
    idx = s.find("static u32 bbr_min_tso_segs_compat(struct sock *sk)")
    if idx < 0:
        raise SystemExit("bbr_min_tso_segs_compat found without insert point")
    insert_after = s.find("}\n\n", idx)
    if insert_after < 0:
        raise SystemExit("unable to insert bbr_main_compat")
    insert_after += 3
    main_wrap = (
        "static void bbr_main_compat(struct sock *sk, const struct rate_sample *rs)\n"
        "{\n"
        "\tbbr_main(sk, 0, 0, rs);\n"
        "}\n\n"
    )
    s = s[:insert_after] + main_wrap + s[insert_after:]

p.write_text(s, encoding='utf-8', newline='\n')
PY

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
import re
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
        "#define __bpf_kfunc __used noinline\n"
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
s = re.sub(r"^#define __bpf_kfunc[^\n]*$", "#define __bpf_kfunc __used noinline", s, count=1, flags=re.MULTILINE)
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
[[ -f "${TCP_BBR}" ]] || fatal "missing patched tcp_bbr.c"
[[ -f "${ICSK_H}" ]] || fatal "missing inet_connection_sock.h"

grep -Eq 'icsk_ca_priv\[[[:space:]]*160[[:space:]]*/[[:space:]]*sizeof\(u64\)\]' "${ICSK_H}" || fatal "ICSK_CA_PRIV_SIZE enlargement missing"

grep -q 'inflight_hi' "${TCP_BBR}" || fatal "BBRv3 feature marker inflight_hi missing"
grep -q 'bw_probe_up_rounds' "${TCP_BBR}" || fatal "BBRv3 feature marker bw_probe_up_rounds missing"
grep -q 'bbr_main_compat' "${TCP_BBR}" || fatal "compat wrapper bbr_main_compat missing"
grep -q 'bbr_min_tso_segs_compat' "${TCP_BBR}" || fatal "compat wrapper bbr_min_tso_segs_compat missing"
grep -q 'BTF_SET8_START(tcp_bbr_check_kfunc_ids)' "${TCP_BBR}" || fatal "BTF_SET8_START conversion missing"
grep -q 'bbr_rs_lost' "${TCP_BBR}" || fatal "compat helper bbr_rs_lost missing"

if grep -Eq "sysctl_tcp_plb_enabled|rs->tx_in_flight|rs->lost|rs->is_ece|rs->is_acking_tlp_retrans_seq|scb->tx.in_flight|scb->tx.lost|TCP_SKB_CB\\(skb\\)->tx.lost|tp->fast_ack_mode = bbr_fast_ack_mode|tp->tlp_orig_data_app_limited|TCP_CONG_WANTS_CE_EVENTS|\\.tso_segs\\s*=|\\.min_tso_segs\\s*=\\s*bbr_tso_segs|\\.skb_marked_lost\\s*=|BTF_KFUNCS_START|BTF_KFUNCS_END" "${TCP_BBR}"; then
  fatal "BBRv3 compat transform incomplete: unresolved 6.1 symbols remain in tcp_bbr.c"
fi

grep -q '#define __bpf_kfunc' "${COMMON_DIR}/include/linux/btf.h" || fatal "__bpf_kfunc macro missing in btf.h"
grep -q '#define BTF_KFUNCS_START' "${COMMON_DIR}/include/linux/btf_ids.h" || fatal "BTF_KFUNCS_START alias missing in btf_ids.h"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "BBRV3_PATCHED=true"
    echo "BBRV3_SOURCE_COMMIT=${BBRV3_COMMIT}"
  } >> "${GITHUB_ENV}"
fi

echo "[BBRv3] full port prepared successfully (commit ${BBRV3_COMMIT})"
