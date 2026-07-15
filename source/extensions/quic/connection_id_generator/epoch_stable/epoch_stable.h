#pragma once

#include <atomic>
#include <cstdint>

#include "source/common/network/reuseport_ebpf_program.h"
#include "source/common/quic/envoy_quic_connection_id_generator_factory.h"

#include "quiche/quic/core/deterministic_connection_id_generator.h"

// All of the eBPF routing machinery requires the ability to attach an eBPF program to the
// reuseport group. Without it the extension is rejected at config load.
#if defined(SO_ATTACH_REUSEPORT_EBPF) && defined(__linux__)
#define ENVOY_EPOCH_STABLE_EBPF_SUPPORTED
#endif

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
  Factory(uint32_t concurrency, Network::ListenSocketFactory& listen_socket_factory);

  ~Factory() override;

  // EnvoyQuicConnectionIdGeneratorFactory.
  QuicConnectionIdGeneratorPtr createQuicConnectionIdGenerator(uint32_t worker_index) override;
  absl::StatusOr<Network::Socket::OptionConstSharedPtr>
  createCompatibleLinuxBpfSocketOption() override;
  QuicConnectionIdWorkerSelector getCompatibleConnectionIdWorkerSelector() override;

private:
#ifdef ENVOY_EPOCH_STABLE_EBPF_SUPPORTED
  absl::Status initialize();
  absl::Status loadMaps(os_fd_t prog_fd);
  absl::Status loadBpfProgram();
  void closeFds();
  absl::Status cleanupAndError(absl::string_view message);
  void registerWorkerSocket(uint32_t worker_index, const Network::Socket& socket);

  Network::ListenSocketFactory& listen_socket_factory_;
  Network::ReuseportEbpfProgramSharedPtr program_;
  const uint32_t concurrency_;
  bool inherited_{false};
  uint8_t current_generation_{0};
  uint8_t num_generations_{0};

  std::atomic<uint32_t> registered_workers_{0};

  // Owns the program fd until it is wrapped in program_.
  os_fd_t prog_fd_{INVALID_SOCKET};
  os_fd_t generations_fd_{INVALID_SOCKET};
  os_fd_t routing_fd_{INVALID_SOCKET};
#endif
};

class Context : public EnvoyQuicConnectionIdGeneratorContext {
public:
  static absl::StatusOr<std::unique_ptr<Context>>
  create(Server::Configuration::FactoryContext& context);

  // EnvoyQuicConnectionIdGeneratorContext.
  EnvoyQuicConnectionIdGeneratorFactoryPtr createQuicConnectionIdGeneratorFactory(
      Network::ListenSocketFactory& listen_socket_factory) override;

private:
  explicit Context(uint32_t concurrency) : concurrency_(concurrency) {}

  const uint32_t concurrency_;
};

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
