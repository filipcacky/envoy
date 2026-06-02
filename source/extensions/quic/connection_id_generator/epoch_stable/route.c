#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/udp.h>

#include "bpf_helpers.h"
#include "routing_config.h"

#define QUIC_PKT_LONG 0x80
#define QUIC_CID_LENGTH 8
#define QUIC_CID_GEN_OFFSET 8
#define QUIC_CID_WITH_ROUTING_LENGTH 9

#define NGEN 16

char _license[] SEC("license") = "Apache-2";

struct reuseport_map {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 65536);
} reuseport_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
  __uint(key_size, sizeof(__u32));
  __uint(max_entries, NGEN);
  __array(values, struct reuseport_map);
} generations SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(struct routing_config));
  __uint(max_entries, 1);
} routing SEC(".maps");

static __always_inline int extract_dcid(unsigned char* start, unsigned char* end,
                                        __u32 udp_payload_offset, __u32* dcid, __u8* gen_byte,
                                        int* is_long) {
  __u32 offset = udp_payload_offset;

  if (start + offset + 1 > end)
    return SK_DROP;

  __u8 flags = start[offset];
  offset += 1;

  __u32 dcid_offset;
  __u8 dcid_len;
  *is_long = (flags & QUIC_PKT_LONG) ? 1 : 0;

  if (*is_long) {
    // Long header: flags(1) | version(4) | dcid_len(1) | dcid(...)
    if (start + offset + 5 > end)
      return SK_DROP;
    dcid_len = start[offset + 4];
    dcid_offset = offset + 5;
  } else {
    // Short header: flags(1) | dcid(...) | gen_byte(1)
    dcid_len = QUIC_CID_WITH_ROUTING_LENGTH;
    dcid_offset = offset;
  }

  if (dcid_len < QUIC_CID_LENGTH || start + dcid_offset + QUIC_CID_LENGTH > end) {
    return SK_DROP;
  }
  *dcid = *(__u32*)(start + dcid_offset);

  if (!*is_long) {
    if (dcid_len < QUIC_CID_WITH_ROUTING_LENGTH ||
        start + dcid_offset + QUIC_CID_WITH_ROUTING_LENGTH > end) {
      return SK_DROP;
    }
    *gen_byte = *(__u8*)(start + dcid_offset + QUIC_CID_GEN_OFFSET);
  }

  return SK_PASS;
}

SEC("sk_reuseport")
int epoch_stable_select_socket(struct sk_reuseport_md* ctx) {
  __u32 zero = 0;
  __u32 dcid = 0;
  __u8 gen_byte = 0;
  int is_long = 0;

  struct routing_config* cfg = bpf_map_lookup_elem(&routing, &zero);
  if (cfg == NULL || cfg->concurrency == 0) {
    return SK_DROP;
  }

  if (extract_dcid(ctx->data, ctx->data_end, sizeof(struct udphdr), &dcid, &gen_byte, &is_long) ==
      SK_DROP) {
    return SK_DROP;
  }

  __u32 gen_idx = is_long ? (cfg->generation % NGEN) : (gen_byte % NGEN);

  void* inner = bpf_map_lookup_elem(&generations, &gen_idx);
  if (inner == NULL) {
    return SK_DROP;
  }

  __u32 worker_key = dcid % cfg->concurrency;
  if (bpf_sk_select_reuseport(ctx, inner, &worker_key, 0) == 0) {
    return SK_PASS;
  }
  return SK_DROP;
}
