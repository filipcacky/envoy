#include <linux/bpf.h>
#include <linux/udp.h>

#include "bpf_helpers.h"
#include "routing_config.h"

#define QUIC_PKT_LONG 0x80
#define QUIC_CID_LENGTH 8
#define QUIC_CID_GEN_OFFSET QUIC_CID_LENGTH
#define QUIC_CID_WORKER_ID_OFFSET (QUIC_CID_LENGTH + 1)
#define QUIC_CID_WITH_ROUTING_LENGTH (QUIC_CID_LENGTH + 2)

#define NGEN 16

char _license[] SEC("license") = "Apache-2";

struct reuseport_map {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, EPOCH_STABLE_MAX_WORKERS);
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

// Short header: flags(1) | dcid(QUIC_CID_WITH_ROUTING_LENGTH)
// Established connections carry the generation and worker index directly in the connection ID.
static __always_inline int handle_short_header(struct sk_reuseport_md* ctx, __u32 offset) {
  if (ctx->data + offset + QUIC_CID_WITH_ROUTING_LENGTH > ctx->data_end) {
    return SK_DROP;
  }

  __u32 generation = *(__u8*)(ctx->data + offset + QUIC_CID_GEN_OFFSET);
  __u32 worker_index = *(__u8*)(ctx->data + offset + QUIC_CID_WORKER_ID_OFFSET);

  void* inner = bpf_map_lookup_elem(&generations, &generation);
  if (inner == NULL) {
    return SK_DROP;
  }

  if (bpf_sk_select_reuseport(ctx, inner, &worker_index, 0) == 0) {
    return SK_PASS;
  }
  return SK_DROP;
}

// Long header: flags(1) | version(4) | dcid_len(1) | dcid(...)
static __always_inline int handle_long_header(struct sk_reuseport_md* ctx, __u32 offset) {
  offset += 4;
  if (ctx->data + offset + 1 + sizeof(__u32) > ctx->data_end) {
    return SK_DROP;
  }
  __u8 dcid_len = ((__u8*)ctx->data)[offset];
  offset += 1;
  if (dcid_len < QUIC_CID_LENGTH) {
    return SK_DROP;
  }
  __u32 stable_dcid_part = *(__u32*)(ctx->data + offset);

  __u32 zero = 0;
  struct routing_config* cfg = bpf_map_lookup_elem(&routing, &zero);
  if (cfg == NULL || cfg->concurrency == 0) {
    return SK_DROP;
  }

  __u32 generation = cfg->generation;
  void* inner = bpf_map_lookup_elem(&generations, &generation);
  if (inner == NULL) {
    return SK_DROP;
  }

  __u32 worker_index = stable_dcid_part % cfg->concurrency;
  if (bpf_sk_select_reuseport(ctx, inner, &worker_index, 0) == 0) {
    return SK_PASS;
  }
  return SK_DROP;
}

SEC("sk_reuseport")
int epoch_stable_select_socket(struct sk_reuseport_md* ctx) {
  __u32 offset = sizeof(struct udphdr);

  if (ctx->data + offset + 1 > ctx->data_end)
    return SK_DROP;

  __u8 flags = ((__u8*)ctx->data)[offset];
  offset += 1;

  if (flags & QUIC_PKT_LONG) {
    return handle_long_header(ctx, offset);
  } else {
    return handle_short_header(ctx, offset);
  }
}
