#pragma once

#include <cstdint>

#include "source/common/common/scoped_fd.h"
#include "source/common/quic/envoy_quic_connection_id_generator_factory.h"

#include "quiche/quic/core/deterministic_connection_id_generator.h"

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {

class EnvoyDeterministicConnectionIdGenerator : public quic::DeterministicConnectionIdGenerator {
public:
  EnvoyDeterministicConnectionIdGenerator(uint32_t connection_id_length, uint8_t generation,
                                          uint8_t worker_index)
      : quic::DeterministicConnectionIdGenerator(connection_id_length), generation_(generation),
        worker_index_(worker_index) {}

  std::optional<quic::QuicConnectionId>
  GenerateNextConnectionId(const quic::QuicConnectionId& original) override;
  std::optional<quic::QuicConnectionId>
  MaybeReplaceConnectionId(const quic::QuicConnectionId& original,
                           const quic::ParsedQuicVersion& version) override;

private:
  uint8_t generation_;
  uint8_t worker_index_;
};

class Factory : public EnvoyQuicConnectionIdGeneratorFactory {
public:
  explicit Factory(Network::ListenSocketFactory& listen_socket_factory);

  // EnvoyQuicConnectionIdGeneratorFactory.
  QuicConnectionIdGeneratorPtr createQuicConnectionIdGenerator(uint32_t worker_index) override;
  absl::StatusOr<Network::Socket::OptionConstSharedPtr>
  createCompatibleLinuxBpfSocketOption(uint32_t concurrency) override;
  QuicConnectionIdWorkerSelector
  getCompatibleConnectionIdWorkerSelector(uint32_t concurrency) override;
  absl::Status registerWorkerSocket(uint32_t worker_index, const Network::Socket& socket) override;

private:
  absl::Status initialize();
  absl::Status loadBpfProgram();
  absl::Status loadMaps();
  absl::Status createGenerationMaps();

  Network::ListenSocketFactory& listen_socket_factory_;
  ScopedFdSharedPtr program_;
  ScopedFd generations_fd_;
  ScopedFd routing_fd_;
  // Latched by createCompatibleLinuxBpfSocketOption.
  uint32_t concurrency_{0};
  uint8_t current_generation_{0};
  uint8_t num_generations_{0};

  uint32_t registered_workers_{0};
};

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
