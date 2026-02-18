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
    "net/ipv4/tcp_cong.c"
    "net/ipv4/tcp_dctcp.c"
    "net/ipv4/tcp_input.c"
    "net/ipv4/tcp_ipv4.c"
    "net/ipv4/tcp_minisocks.c"
    "net/ipv4/tcp_output.c"
    "net/ipv4/tcp_plb.c"
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
      git -C "${COMMON_DIR}" checkout --ours -- include/net/tcp.h net/ipv4/tcp_rate.c || return 1
      python3 - "${COMMON_DIR}" <<'PY' || return 1
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
    insert = anchor + (
        "\n"
        "static inline u32 tcp_stamp32_us_delta(u32 t1, u32 t0)\n"
        "{\n"
        "\treturn max_t(s32, t1 - t0, 0);\n"
        "}\n"
    )
    if anchor not in s:
        raise SystemExit("failed to locate tcp_stamp_us_delta() anchor in include/net/tcp.h")
    s = s.replace(anchor, insert, 1)

if "u32 first_tx_mstamp;" not in s:
    s_new = re.sub(r'(\s)u64(\s+first_tx_mstamp;)', r'\1u32\2', s, count=1)
    if s_new == s:
        raise SystemExit("failed to rewrite first_tx_mstamp type in include/net/tcp.h")
    s = s_new
if "u32 delivered_mstamp;" not in s:
    s_new = re.sub(r'(\s)u64(\s+delivered_mstamp;)', r'\1u32\2', s, count=1)
    if s_new == s:
        raise SystemExit("failed to rewrite delivered_mstamp type in include/net/tcp.h")
    s = s_new
tcp_h.write_text(s, encoding="utf-8", newline="\n")

t = tcp_rate.read_text(encoding="utf-8")
if not re.search(r'tcp_stamp32_us_delta\(\s*tp->first_tx_mstamp\s*,', t):
    t_new, n = re.subn(
        r'tcp_stamp_us_delta\(\s*tp->first_tx_mstamp\s*,',
        'tcp_stamp32_us_delta(tp->first_tx_mstamp,',
        t,
        count=1,
    )
    if n != 1:
        raise SystemExit("failed to rewrite send-phase timestamp helper in net/ipv4/tcp_rate.c")
    t = t_new
if not re.search(r'tcp_stamp32_us_delta\(\s*tp->tcp_mstamp\s*,', t):
    t_new, n = re.subn(
        r'tcp_stamp_us_delta\(\s*tp->tcp_mstamp\s*,',
        'tcp_stamp32_us_delta(tp->tcp_mstamp,',
        t,
        count=1,
    )
    if n != 1:
        raise SystemExit("failed to rewrite ack-phase timestamp helper in net/ipv4/tcp_rate.c")
    t = t_new
tcp_rate.write_text(t, encoding="utf-8", newline="\n")
PY
      git -C "${COMMON_DIR}" add -- include/net/tcp.h net/ipv4/tcp_rate.c || return 1
      return 0
      ;;
    0e6b4413cb4a)
      echo "[BBRv3] resolving known 3-way conflict for ${short_sha} with upstream-equivalent edits"
      git -C "${COMMON_DIR}" checkout --ours -- include/net/tcp.h net/ipv4/tcp_output.c net/ipv4/tcp_rate.c || return 1
      python3 - "${COMMON_DIR}" <<'PY' || return 1
from pathlib import Path
import sys

root = Path(sys.argv[1])
tcp_h = root / "include/net/tcp.h"
tcp_output = root / "net/ipv4/tcp_output.c"
tcp_rate = root / "net/ipv4/tcp_rate.c"

def insert_after_line(text: str, needle: str, addition: str) -> str:
    idx = text.find(needle)
    if idx < 0:
        raise SystemExit(f"failed to locate line anchor: {needle}")
    end = text.find("\n", idx)
    if end < 0:
        raise SystemExit(f"failed to locate newline for anchor: {needle}")
    end += 1
    return text[:end] + addition + text[end:]

s = tcp_h.read_text(encoding="utf-8")
if "#define TCPCB_IN_FLIGHT_BITS 20" not in s:
    anchor = "\t\t\tu32 delivered_mstamp;\n"
    addition = (
        "#define TCPCB_IN_FLIGHT_BITS 20\n"
        "#define TCPCB_IN_FLIGHT_MAX ((1U << TCPCB_IN_FLIGHT_BITS) - 1)\n"
        "\t\t\tu32 in_flight:20,   /* packets in flight at transmit */\n"
        "\t\t\t    unused2:12;\n"
    )
    s = insert_after_line(s, anchor, addition)

if "u32 tx_in_flight;" not in s:
    anchor = "\tu32  prior_delivered_ce;/* tp->delivered_ce at \"prior_mstamp\" */\n"
    addition = "\tu32 tx_in_flight;\t/* packets in flight at starting timestamp */\n"
    s = insert_after_line(s, anchor, addition)

if "void tcp_set_tx_in_flight(struct sock *sk, struct sk_buff *skb);" not in s:
    anchor = "void tcp_rate_skb_sent(struct sock *sk, struct sk_buff *skb);\n"
    s = s.replace(anchor, "void tcp_set_tx_in_flight(struct sock *sk, struct sk_buff *skb);\n" + anchor, 1)

tcp_h.write_text(s, encoding="utf-8", newline="\n")

o = tcp_output.read_text(encoding="utf-8")
if "tcp_set_tx_in_flight(sk, skb);" not in o:
    anchor = "\t\t\ttcp_init_tso_segs(skb, mss_now);\n"
    o = insert_after_line(o, anchor, "\t\t\ttcp_set_tx_in_flight(sk, skb);\n")
tcp_output.write_text(o, encoding="utf-8", newline="\n")

r = tcp_rate.read_text(encoding="utf-8")
if "void tcp_set_tx_in_flight(struct sock *sk, struct sk_buff *skb)" not in r:
    anchor = "/* Snapshot the current delivery information in the skb, to generate\n"
    helper = (
        "void tcp_set_tx_in_flight(struct sock *sk, struct sk_buff *skb)\n"
        "{\n"
        "\tstruct tcp_sock *tp = tcp_sk(sk);\n"
        "\tu32 in_flight;\n"
        "\n"
        "\t/* Check, sanitize, and record packets in flight after skb was sent. */\n"
        "\tin_flight = tcp_packets_in_flight(tp) + tcp_skb_pcount(skb);\n"
        "\tif (WARN_ONCE(in_flight > TCPCB_IN_FLIGHT_MAX,\n"
        "\t\t      \"insane in_flight %u cc %s mss %u \"\n"
        "\t\t      \"cwnd %u pif %u %u %u %u\\n\",\n"
        "\t\t      in_flight, inet_csk(sk)->icsk_ca_ops->name,\n"
        "\t\t      tp->mss_cache, tp->snd_cwnd,\n"
        "\t\t      tp->packets_out, tp->retrans_out,\n"
        "\t\t      tp->sacked_out, tp->lost_out))\n"
        "\t\tin_flight = TCPCB_IN_FLIGHT_MAX;\n"
        "\tTCP_SKB_CB(skb)->tx.in_flight = in_flight;\n"
        "}\n"
        "\n"
    )
    r = r.replace(anchor, helper + anchor, 1)

if "tcp_set_tx_in_flight(sk, skb);" not in r:
    anchor = "TCP_SKB_CB(skb)->tx.is_app_limited"
    idx = r.find(anchor)
    if idx < 0:
        raise SystemExit("failed to locate is_app_limited assignment in net/ipv4/tcp_rate.c")
    end = r.find("\n", idx)
    if end < 0:
        raise SystemExit("failed to locate line ending for is_app_limited assignment")
    end += 1
    r = r[:end] + "\ttcp_set_tx_in_flight(sk, skb);\n" + r[end:]

if "rs->tx_in_flight" not in r:
    anchor = "rs->is_retrans"
    idx = r.find(anchor)
    if idx < 0:
        raise SystemExit("failed to locate rs->is_retrans assignment in net/ipv4/tcp_rate.c")
    end = r.find("\n", idx)
    if end < 0:
        raise SystemExit("failed to locate line ending for rs->is_retrans assignment")
    end += 1
    r = r[:end] + "\t\trs->tx_in_flight     = scb->tx.in_flight;\n" + r[end:]

tcp_rate.write_text(r, encoding="utf-8", newline="\n")
PY
      git -C "${COMMON_DIR}" add -- include/net/tcp.h net/ipv4/tcp_output.c net/ipv4/tcp_rate.c || return 1
      return 0
      ;;
    5093de531d14)
      echo "[BBRv3] resolving known 3-way conflict for ${short_sha} with upstream-equivalent edits"
      git -C "${COMMON_DIR}" checkout --ours -- include/net/tcp.h net/ipv4/tcp_output.c || return 1
      python3 - "${COMMON_DIR}" <<'PY' || return 1
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
tcp_h = root / "include/net/tcp.h"
tcp_output = root / "net/ipv4/tcp_output.c"

s = tcp_h.read_text(encoding="utf-8")
if "tcp_skb_tx_in_flight_is_suspicious" not in s:
    fn = re.search(r'static inline bool tcp_skb_sent_after\(.*?\n\}\n', s, flags=re.S)
    if not fn:
        raise SystemExit("failed to locate tcp_skb_sent_after() in include/net/tcp.h")
    helper = (
        "\n"
        "/* If a retransmit failed due to local qdisc congestion or other local issues,\n"
        " * then we may have called tcp_set_skb_tso_segs() to increase the number of\n"
        " * segments in the skb without increasing the tx.in_flight. In all other cases,\n"
        " * the tx.in_flight should be at least as big as the pcount of the sk_buff.  We\n"
        " * do not have the state to know whether a retransmit failed due to local qdisc\n"
        " * congestion or other local issues, so to avoid spurious warnings we consider\n"
        " * that any skb marked lost may have suffered that fate.\n"
        " */\n"
        "static inline bool tcp_skb_tx_in_flight_is_suspicious(u32 skb_pcount,\n"
        "\t\t\t\t\t      u32 skb_sacked_flags,\n"
        "\t\t\t\t\t      u32 tx_in_flight)\n"
        "{\n"
        "\treturn (skb_pcount > tx_in_flight) && !(skb_sacked_flags & TCPCB_LOST);\n"
        "}\n"
    )
    s = s[:fn.end()] + helper + s[fn.end():]
tcp_h.write_text(s, encoding="utf-8", newline="\n")

o = tcp_output.read_text(encoding="utf-8")
if "int nsize, old_factor, inflight_prev;" not in o:
    o = o.replace("int nsize, old_factor;", "int nsize, old_factor, inflight_prev;", 1)
if "TCP_SKB_CB(buff)->tx.in_flight = inflight_prev +" not in o:
    anchor = "\t\tif (diff)\n\t\t\ttcp_adjust_pcount(sk, skb, diff);\n"
    block = (
        "\n"
        "\t\tinflight_prev = TCP_SKB_CB(skb)->tx.in_flight - old_factor;\n"
        "\t\tif (inflight_prev < 0) {\n"
        "\t\t\tWARN_ONCE(tcp_skb_tx_in_flight_is_suspicious(\n"
        "\t\t\t\t\t  old_factor,\n"
        "\t\t\t\t\t  TCP_SKB_CB(skb)->sacked,\n"
        "\t\t\t\t\t  TCP_SKB_CB(skb)->tx.in_flight),\n"
        "\t\t\t\t  \"inconsistent: tx.in_flight: %u \"\n"
        "\t\t\t\t  \"old_factor: %d mss: %u sacked: %u \"\n"
        "\t\t\t\t  \"1st pcount: %d 2nd pcount: %d \"\n"
        "\t\t\t\t  \"1st len: %u 2nd len: %u \",\n"
        "\t\t\t\t  TCP_SKB_CB(skb)->tx.in_flight, old_factor,\n"
        "\t\t\t\t  mss_now, TCP_SKB_CB(skb)->sacked,\n"
        "\t\t\t\t  tcp_skb_pcount(skb), tcp_skb_pcount(buff),\n"
        "\t\t\t\t  skb->len, buff->len);\n"
        "\t\t\tinflight_prev = 0;\n"
        "\t\t}\n"
        "\t\t/* Set 1st tx.in_flight as if 1st were sent by itself: */\n"
        "\t\tTCP_SKB_CB(skb)->tx.in_flight = inflight_prev +\n"
        "\t\t\t\t\t\t tcp_skb_pcount(skb);\n"
        "\t\t/* Set 2nd tx.in_flight with new 1st and 2nd pcounts: */\n"
        "\t\tTCP_SKB_CB(buff)->tx.in_flight = inflight_prev +\n"
        "\t\t\t\t\t\t tcp_skb_pcount(skb) +\n"
        "\t\t\t\t\t\t tcp_skb_pcount(buff);\n"
    )
    if anchor not in o:
        raise SystemExit("failed to locate tcp_fragment() pcount adjustment anchor in net/ipv4/tcp_output.c")
    o = o.replace(anchor, anchor + block, 1)
tcp_output.write_text(o, encoding="utf-8", newline="\n")
PY
      git -C "${COMMON_DIR}" add -- include/net/tcp.h net/ipv4/tcp_output.c || return 1
      return 0
      ;;
    9163f4486be7)
      echo "[BBRv3] resolving known 3-way conflict for ${short_sha} with upstream-equivalent edits"
      git -C "${COMMON_DIR}" checkout --ours -- include/net/tcp.h net/ipv4/bpf_tcp_ca.c net/ipv4/tcp_bbr.c net/ipv4/tcp_output.c || return 1
      python3 - "${COMMON_DIR}" <<'PY' || return 1
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
tcp_h = root / "include/net/tcp.h"
bpf_tcp_ca = root / "net/ipv4/bpf_tcp_ca.c"
tcp_bbr = root / "net/ipv4/tcp_bbr.c"
tcp_output = root / "net/ipv4/tcp_output.c"

h = tcp_h.read_text(encoding="utf-8")
if "u32 (*tso_segs)(struct sock *sk, unsigned int mss_now);" not in h:
    h_new = h.replace(
        "u32 (*min_tso_segs)(struct sock *sk);",
        "u32 (*tso_segs)(struct sock *sk, unsigned int mss_now);",
        1,
    )
    if h_new == h:
        raise SystemExit("failed to update tcp_congestion_ops tso callback signature")
    h = h_new
tcp_h.write_text(h, encoding="utf-8", newline="\n")

b = bpf_tcp_ca.read_text(encoding="utf-8")
if "static u32 bpf_tcp_ca_tso_segs(struct sock *sk, unsigned int mss_now)" not in b:
    b_new, n = re.subn(
        r'static u32 bpf_tcp_ca_(?:min_tso_segs|tso_segs)\(struct sock \*sk\)',
        'static u32 bpf_tcp_ca_tso_segs(struct sock *sk, unsigned int mss_now)',
        b,
        count=1,
    )
    if n == 0 and "bpf_tcp_ca_tso_segs(" not in b:
        pkts_anchor = re.search(r'static void bpf_tcp_ca_pkts_acked\(.*?\n\}\n', b, flags=re.S)
        if pkts_anchor:
            insert_pos = pkts_anchor.end()
        else:
            insert_pos = b.find("struct bpf_struct_ops bpf_tcp_congestion_ops")
            if insert_pos < 0:
                raise SystemExit("failed to find insertion point for bpf_tcp_ca_tso_segs()")
        stub = (
            "\nstatic u32 bpf_tcp_ca_tso_segs(struct sock *sk, unsigned int mss_now)\n"
            "{\n"
            "\treturn 0;\n"
            "}\n"
        )
        b = b[:insert_pos] + stub + b[insert_pos:]
    elif n == 1:
        b = b_new
if ".tso_segs = bpf_tcp_ca_tso_segs," not in b:
    b_new, n = re.subn(
        r'\.min_tso_segs\s*=\s*bpf_tcp_ca_(?:min_tso_segs|tso_segs),',
        '.tso_segs = bpf_tcp_ca_tso_segs,',
        b,
        count=1,
    )
    if n == 0:
        b_new, n = re.subn(
            r'(\.pkts_acked\s*=\s*bpf_tcp_ca_pkts_acked,\n)',
            r'\1\t.tso_segs = bpf_tcp_ca_tso_segs,\n',
            b,
            count=1,
        )
    if n == 0:
        b_new, n = re.subn(
            r'(\.cong_control\s*=\s*bpf_tcp_ca_cong_control,\n)',
            '\t.tso_segs = bpf_tcp_ca_tso_segs,\n\\1',
            b,
            count=1,
        )
    if n == 0:
        b_new = b
    b = b_new
bpf_tcp_ca.write_text(b, encoding="utf-8", newline="\n")

o = tcp_output.read_text(encoding="utf-8")
if "ca_ops->min_tso_segs" in o:
    old_block = (
        "\tmin_tso = ca_ops->min_tso_segs ?\n"
        "\t\t\tca_ops->min_tso_segs(sk) :\n"
        "\t\t\tREAD_ONCE(sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs);\n"
        "\n"
        "\ttso_segs = tcp_tso_autosize(sk, mss_now, min_tso);\n"
    )
    new_block = (
        "\ttso_segs = ca_ops->tso_segs ?\n"
        "\t\tca_ops->tso_segs(sk, mss_now) :\n"
        "\t\ttcp_tso_autosize(sk, mss_now,\n"
        "\t\t\t\t sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs);\n"
    )
    if old_block not in o:
        o = re.sub(
            r'\s*min_tso\s*=\s*ca_ops->min_tso_segs[\s\S]*?tso_segs\s*=\s*tcp_tso_autosize\(sk,\s*mss_now,\s*min_tso\);\n',
            "\n" + new_block,
            o,
            count=1,
        )
    else:
        o = o.replace(old_block, new_block, 1)
o = o.replace("u32 min_tso, tso_segs;", "u32 tso_segs;")
tcp_output.write_text(o, encoding="utf-8", newline="\n")

t = tcp_bbr.read_text(encoding="utf-8")
if "static u32 bbr_tso_segs_generic(struct sock *sk, unsigned int mss_now," not in t:
    min_fn = re.search(r'(?:__bpf_kfunc\s+)?static u32 bbr_min_tso_segs\(struct sock \*sk\)\n\{.*?\n\}\n', t, flags=re.S)
    if not min_fn:
        raise SystemExit("failed to locate bbr_min_tso_segs() in tcp_bbr.c")
    add = (
        "\n/* Return the number of segments BBR would like in a TSO/GSO skb, given\n"
        " * a particular max gso size as a constraint.\n"
        " */\n"
        "static u32 bbr_tso_segs_generic(struct sock *sk, unsigned int mss_now,\n"
        "\t\t\t\tu32 gso_max_size)\n"
        "{\n"
        "\tu32 segs;\n"
        "\tu64 bytes;\n"
        "\n"
        "\t/* Budget a TSO/GSO burst size allowance based on bw (pacing_rate). */\n"
        "\tbytes = READ_ONCE(sk->sk_pacing_rate) >> READ_ONCE(sk->sk_pacing_shift);\n"
        "\n"
        "\tbytes = min_t(u32, bytes, gso_max_size - 1 - MAX_TCP_HEADER);\n"
        "\tsegs = max_t(u32, bytes / mss_now, bbr_min_tso_segs(sk));\n"
        "\treturn segs;\n"
        "}\n"
        "\n"
        "/* Custom tcp_tso_autosize() for BBR, used at transmit time to cap skb size. */\n"
        "static u32  bbr_tso_segs(struct sock *sk, unsigned int mss_now)\n"
        "{\n"
        "\treturn bbr_tso_segs_generic(sk, mss_now, sk->sk_gso_max_size);\n"
        "}\n"
        "\n"
        "/* Like bbr_tso_segs(), using mss_cache, ignoring driver's sk_gso_max_size. */\n"
    )
    t = t[:min_fn.end()] + add + t[min_fn.end():]

goal_pat = re.compile(r'static u32 bbr_tso_segs_goal\(struct sock \*sk\)\n\{[\s\S]*?\n\}', re.S)
goal_repl = (
    "static u32 bbr_tso_segs_goal(struct sock *sk)\n"
    "{\n"
    "\tstruct tcp_sock *tp = tcp_sk(sk);\n"
    "\n"
    "\treturn  bbr_tso_segs_generic(sk, tp->mss_cache, GSO_MAX_SIZE);\n"
    "}"
)
t, goal_n = goal_pat.subn(goal_repl, t, count=1)
if goal_n != 1:
    raise SystemExit("failed to rewrite bbr_tso_segs_goal()")

if ".tso_segs\t= bbr_tso_segs," not in t and ".tso_segs = bbr_tso_segs," not in t:
    t_new = t.replace(".min_tso_segs\t= bbr_min_tso_segs,", ".tso_segs\t= bbr_tso_segs,", 1)
    if t_new == t:
        t_new = t.replace(".min_tso_segs = bbr_min_tso_segs,", ".tso_segs = bbr_tso_segs,", 1)
    if t_new == t:
        raise SystemExit("failed to switch tcp_bbr_cong_ops to tso_segs callback")
    t = t_new

tcp_bbr.write_text(t, encoding="utf-8", newline="\n")
PY
      git -C "${COMMON_DIR}" add -- include/net/tcp.h net/ipv4/bpf_tcp_ca.c net/ipv4/tcp_bbr.c net/ipv4/tcp_output.c || return 1
      return 0
      ;;
    4d2e56435d43)
      echo "[BBRv3] resolving known 3-way conflict for ${short_sha} with upstream-equivalent edits"
      git -C "${COMMON_DIR}" checkout --ours -- include/linux/tcp.h net/ipv4/tcp.c net/ipv4/tcp_cong.c net/ipv4/tcp_input.c || return 1
      python3 - "${COMMON_DIR}" <<'PY' || return 1
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
linux_tcp = root / "include/linux/tcp.h"
tcp_c = root / "net/ipv4/tcp.c"
tcp_cong = root / "net/ipv4/tcp_cong.c"
tcp_input = root / "net/ipv4/tcp_input.c"

s = linux_tcp.read_text(encoding="utf-8")
if "fast_ack_mode" not in s:
    s_new, n = re.subn(
        r'(u8\s+dup_ack_counter:2,\n\s*tlp_retrans:1,\s*/\* TLP is a retransmission \*/\n\s*)unused:5;',
        r'\1fast_ack_mode:1,\t/* ack ASAP if >1 rcv_mss received? */\n\t\tunused:4;',
        s,
        count=1,
    )
    if n != 1:
        raise SystemExit("failed to add fast_ack_mode bitfield in include/linux/tcp.h")
    s = s_new
linux_tcp.write_text(s, encoding="utf-8", newline="\n")

c = tcp_c.read_text(encoding="utf-8")
if "tp->fast_ack_mode = 0;" not in c:
    anchor = "\ttp->rcv_ooopack = 0;\n"
    if anchor not in c:
        raise SystemExit("failed to locate rcv_ooopack reset in net/ipv4/tcp.c")
    c = c.replace(anchor, anchor + "\ttp->fast_ack_mode = 0;\n", 1)
tcp_c.write_text(c, encoding="utf-8", newline="\n")

g = tcp_cong.read_text(encoding="utf-8")
if "tcp_sk(sk)->fast_ack_mode = 0;" not in g:
    anchor = "\ttcp_sk(sk)->prior_ssthresh = 0;\n"
    if anchor not in g:
        raise SystemExit("failed to locate prior_ssthresh reset in net/ipv4/tcp_cong.c")
    g = g.replace(anchor, anchor + "\ttcp_sk(sk)->fast_ack_mode = 0;\n", 1)
tcp_cong.write_text(g, encoding="utf-8", newline="\n")

i = tcp_input.read_text(encoding="utf-8")
if "tp->fast_ack_mode == 1 ||" not in i:
    anchor = "if (((tp->rcv_nxt - tp->rcv_wup) > inet_csk(sk)->icsk_ack.rcv_mss &&\n"
    if anchor not in i:
        raise SystemExit("failed to locate __tcp_ack_snd_check() rcv_mss condition in net/ipv4/tcp_input.c")
    i = i.replace(anchor, anchor + "\t     (tp->fast_ack_mode == 1 ||\n", 1)
    close_old = "\t     __tcp_select_window(sk) >= tp->rcv_wnd)) ||\n"
    close_new = "\t     __tcp_select_window(sk) >= tp->rcv_wnd))) ||\n"
    if close_old in i:
        i = i.replace(close_old, close_new, 1)
    else:
        close_old = "     __tcp_select_window(sk) >= tp->rcv_wnd)) ||\n"
        if close_old in i:
            i = i.replace(close_old, "     __tcp_select_window(sk) >= tp->rcv_wnd))) ||\n", 1)
        else:
            raise SystemExit("failed to update __tcp_ack_snd_check() fast_ack_mode closing condition")
tcp_input.write_text(i, encoding="utf-8", newline="\n")
PY
      git -C "${COMMON_DIR}" add -- include/linux/tcp.h net/ipv4/tcp.c net/ipv4/tcp_cong.c net/ipv4/tcp_input.c || return 1
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
