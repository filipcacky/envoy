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
  explicit EpochStableConfig(uint32_t max_map_entries, uint8_t active_map_index)
      : max_map_entries(max_map_entries), active_map_index(active_map_index) {}
  // TODO(filipcacky): use envoy limits?
  uint32_t max_map_entries;

  uint32_t active_map_index;
};

// This class modifies connection ids that are too long in an Envoy fashion.
class EnvoyDeterministicConnectionIdGenerator : public quic::DeterministicConnectionIdGenerator {
public:
  EnvoyDeterministicConnectionIdGenerator(uint32_t connection_id_length, uint8_t map_index)
      : quic::DeterministicConnectionIdGenerator(connection_id_length), map_index_(map_index) {}

  // Hashes |original| to create a new connection ID in Envoy fashion.
  absl::optional<quic::QuicConnectionId>
  GenerateNextConnectionId(const quic::QuicConnectionId& original) override;
  // Replace the connection ID if and only if |original| is not of the expected
  // length in Envoy fashion.
  absl::optional<quic::QuicConnectionId>
  MaybeReplaceConnectionId(const quic::QuicConnectionId& original,
                           const quic::ParsedQuicVersion& version) override;

private:
  uint8_t map_index_;
};

class Factory : public EnvoyQuicConnectionIdGeneratorFactory {
public:
  static absl::StatusOr<std::unique_ptr<Factory>> create(const EpochStableConfig& config);

  ~Factory() override;

  QuicConnectionIdGeneratorPtr createQuicConnectionIdGenerator(uint32_t worker_index) override;
  absl::StatusOr<Network::Socket::OptionConstSharedPtr>
  createCompatibleLinuxBpfSocketOption(uint32_t concurrency, os_fd_t prog_fd) override;
  QuicConnectionIdWorkerSelector
  getCompatibleConnectionIdWorkerSelector(uint32_t concurrency) override;
  QuicConnectionIdObserverPtr createConnectionIdObserver() override;
  bool hasStatefulConnectionIdWorkerSelector() const override { return true; }
  os_fd_t bpfProgFd() const override { return prog_fd_; }
  void registerWorkerSocket(uint32_t worker_index, const Network::Socket& socket) override;

private:
  Factory(const EpochStableConfig& config);

  absl::Status loadMaps(os_fd_t);
  absl::Status loadBpfProgram();
  absl::Status cleanupAndError(absl::string_view message);

  const EpochStableConfig config_;

  os_fd_t prog_fd_{INVALID_SOCKET};
#if defined(__linux__)
  uint32_t concurrency_{0};
  std::atomic<uint32_t> registered_workers_{0};
  os_fd_t map1_fd_{INVALID_SOCKET};
  os_fd_t map2_fd_{INVALID_SOCKET};
  os_fd_t active_map_fd_{INVALID_SOCKET};
  os_fd_t concurrency_fd_{INVALID_SOCKET};
#endif
};

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
