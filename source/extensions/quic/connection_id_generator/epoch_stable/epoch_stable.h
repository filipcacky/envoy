#pragma once

#include <atomic>
#include <cstdint>

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
  explicit EpochStableConfig(uint32_t max_map_entries) : max_map_entries(max_map_entries) {}

  uint32_t max_map_entries;
};

class EnvoyDeterministicConnectionIdGenerator : public quic::DeterministicConnectionIdGenerator {
public:
  EnvoyDeterministicConnectionIdGenerator(uint32_t connection_id_length, uint8_t generation)
      : quic::DeterministicConnectionIdGenerator(connection_id_length), generation_(generation) {}

  absl::optional<quic::QuicConnectionId>
  GenerateNextConnectionId(const quic::QuicConnectionId& original) override;
  absl::optional<quic::QuicConnectionId>
  MaybeReplaceConnectionId(const quic::QuicConnectionId& original,
                           const quic::ParsedQuicVersion& version) override;

private:
  uint8_t generation_;
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
  uint8_t num_generations_{0};
  uint8_t current_generation_{0};

  std::atomic<uint32_t> registered_workers_{0};

  os_fd_t generations_fd_{INVALID_SOCKET};
  os_fd_t routing_fd_{INVALID_SOCKET};
#endif
};

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
