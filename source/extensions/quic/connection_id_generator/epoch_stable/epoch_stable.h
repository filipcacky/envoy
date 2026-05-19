#pragma once

#include <atomic>
#include <string>

#include "source/common/quic/envoy_quic_connection_id_generator_factory.h"

#include "quiche/quic/core/deterministic_connection_id_generator.h"

#if defined(__linux__)
struct bpf_object;
#endif

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {

struct EpochStableConfig {
  EpochStableConfig(uint32_t max_map_entries, std::string bpf_pin_path)
      : max_map_entries(max_map_entries), bpf_pin_path(std::move(bpf_pin_path)) {}
  // TODO(filipcacky): use envoy limits?
  uint32_t max_map_entries;
  // TODO(filipcacky): pass fd via hotrestarter without pinning?
  std::string bpf_pin_path;
};

class EpochStableConnectionIdObserver : public QuicConnectionIdObserver {
public:
  EpochStableConnectionIdObserver(int socket_map_fd, uint32_t concurrency);

  void onConnectionIdIssued(const quic::QuicConnectionId& connection_id,
                            const Network::Socket& socket) override;
  void onConnectionIdRetired(const quic::QuicConnectionId& connection_id) override;

private:
  static uint64_t cidToKey(const quic::QuicConnectionId& cid);

  const int socket_map_fd_;
  const uint32_t concurrency_;
};

class Factory : public EnvoyQuicConnectionIdGeneratorFactory {
public:
  static absl::StatusOr<std::unique_ptr<Factory>> create(const EpochStableConfig& config);

  ~Factory() override;

  QuicConnectionIdGeneratorPtr createQuicConnectionIdGenerator(uint32_t worker_index) override;
  absl::StatusOr<Network::Socket::OptionConstSharedPtr>
  createCompatibleLinuxBpfSocketOption(uint32_t concurrency) override;
  QuicConnectionIdWorkerSelector
  getCompatibleConnectionIdWorkerSelector(uint32_t concurrency) override;
  QuicConnectionIdObserverPtr createConnectionIdObserver() override;
  bool hasStatefulConnectionIdWorkerSelector() const override { return true; }
  void registerWorkerSocket(uint32_t worker_index, const Network::Socket& socket) override;

private:
  Factory(const EpochStableConfig& config);

  absl::Status loadPinnedMaps();
  absl::Status pinProgram();
  absl::Status loadBpfProgram();
  absl::Status cleanupAndError(absl::string_view message);

  const EpochStableConfig config_;

#if defined(__linux__)
  uint32_t concurrency_{0};
  std::atomic<uint32_t> registered_workers_{0};
  int socket_map_fd_{-1};
  int concurrency_fd_{-1};
  int prog_fd_{-1};
  struct bpf_object* bpf_obj_{nullptr};
#endif
};

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
