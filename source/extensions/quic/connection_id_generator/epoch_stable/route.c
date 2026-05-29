#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/udp.h>

#include "bpf_helpers.h"

#define QUIC_PKT_LONG 0x80
#define QUIC_CID_LENGTH 8
#define QUIC_CID_WITH_EPOCH_LENGTH 9
#define QUIC_CID_KEY_SIZE sizeof(__u64)

char _license[] SEC("license") = "Apache-2";

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 65536);
} map1 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 65536);
} map2 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 1);
} concurrency SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 1);
} active_map SEC(".maps");

static __always_inline int extract_dcid(unsigned char* start, unsigned char* end,
                                        __u32 udp_payload_offset, __u32* dcid,
                                        __u32* packet_active_map) {
  __u32 offset = udp_payload_offset;

  if (start + offset + 1 > end)
    return SK_DROP;

  __u8 flags = start[offset];
  offset += 1;

  __u32 dcid_offset;
  __u8 dcid_len;
  __u8 is_long = flags & QUIC_PKT_LONG;

  if (is_long) {
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

  if (!is_long) {
    if (start + dcid_offset + QUIC_CID_WITH_EPOCH_LENGTH > end) {
      return SK_DROP;
    }

    *packet_active_map = *(__u8*)(start + dcid_offset + QUIC_CID_LENGTH);
  }

  return SK_PASS;
}

SEC("sk_reuseport")
int epoch_stable_select_socket(struct sk_reuseport_md* ctx) {
  int rc;
  __u32 dcid;
  __u32 packet_active_map;
  __u32 zero = 0;

  __u32* actual_active_map = bpf_map_lookup_elem(&active_map, &zero);
  if (actual_active_map == NULL) {
    return SK_DROP;
  }

  packet_active_map = *actual_active_map;

  rc = extract_dcid(ctx->data, ctx->data_end, sizeof(struct udphdr), &dcid, &packet_active_map);
  if (rc == SK_DROP) {
    return rc;
  }

  __u32* actual_concurrency = bpf_map_lookup_elem(&concurrency, &zero);
  if (actual_concurrency == NULL || *actual_concurrency == 0) {
    return SK_DROP;
  }

  void* map = packet_active_map == 0 ? &map1 : &map2;

  __u32 worker_key = dcid % *actual_concurrency;
  rc = bpf_sk_select_reuseport(ctx, map, &worker_key, 0);
  if (rc == 0) {
    return SK_PASS;
  }

  return SK_DROP;
}
