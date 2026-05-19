#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/udp.h>

#include "bpf_helpers.h"

#define QUIC_PKT_LONG 0x80
#define QUIC_CID_LENGTH 8
#define QUIC_CID_KEY_SIZE sizeof(__u64)

char _license[] SEC("license") = "Apache-2";

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __uint(key_size, QUIC_CID_KEY_SIZE);
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 65536);
} socket_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 1);
} concurrency SEC(".maps");

static __always_inline int extract_dcid(unsigned char* start, unsigned char* end,
                                        __u32 udp_payload_offset, __u64* dcid) {
  __u32 offset = udp_payload_offset;

  if (start + offset + 1 > end)
    return SK_DROP;

  __u8 flags = start[offset];
  offset += 1;

  __u32 dcid_offset;
  __u8 dcid_len;

  if (flags & QUIC_PKT_LONG) {
    // Long header: flags(1) | version(4) | dcid_len(1) | dcid(...)
    if (start + offset + 5 > end)
      return SK_DROP;

    dcid_len = start[offset + 4];
    dcid_offset = offset + 5;
  } else {
    // Short header / gQUIC: flags(1) | dcid(...)
    dcid_len = QUIC_CID_LENGTH;
    dcid_offset = offset;
  }

  if (dcid_len < QUIC_CID_LENGTH || start + dcid_offset + QUIC_CID_LENGTH > end) {
    return SK_DROP;
  }

  *dcid = *(__u64*)(start + dcid_offset);

  return SK_PASS;
}

SEC("sk_reuseport")
int epoch_stable_select_socket(struct sk_reuseport_md* ctx) {
  int rc;
  __u64 dcid;

  rc = extract_dcid(ctx->data, ctx->data_end, sizeof(struct udphdr), &dcid);
  if (rc == SK_DROP) {
    return rc;
  }

  rc = bpf_sk_select_reuseport(ctx, &socket_map, &dcid, 0);
  if (rc == 0) {
    return SK_PASS;
  }

  if (rc != -ENOENT) {
    return SK_DROP;
  }

  __u32 zero = 0;
  __u32* total = bpf_map_lookup_elem(&concurrency, &zero);
  if (total == NULL || *total == 0) {
    return SK_DROP;
  }

  __u64 worker_key = dcid % *total;
  rc = bpf_sk_select_reuseport(ctx, &socket_map, &worker_key, 0);
  if (rc == 0) {
    return SK_PASS;
  }

  return SK_DROP;
}
