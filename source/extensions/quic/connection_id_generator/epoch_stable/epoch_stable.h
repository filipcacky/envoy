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
  explicit EpochStableConfig(uint32_t max_map_entries) : max_map_entries(max_map_entries) {}
  // TODO(filipcacky): use envoy limits?
  uint32_t max_map_entries;
};

class EpochStableConnectionIdObserver : public QuicConnectionIdObserver {
public:
  EpochStableConnectionIdObserver(os_fd_t cid_map_fd, uint32_t concurrency);

  void onConnectionIdIssued(const quic::QuicConnectionId& connection_id,
                            const Network::Socket& socket) override;
  void onConnectionIdRetired(const quic::QuicConnectionId& connection_id) override;

private:
  static uint64_t cidToKey(const quic::QuicConnectionId& cid);

  const os_fd_t cid_map_fd_;
  const uint32_t concurrency_;
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
  os_fd_t cid_map_fd_{INVALID_SOCKET};
  os_fd_t listen_map_fd_{INVALID_SOCKET};
  os_fd_t concurrency_fd_{INVALID_SOCKET};
#endif
};

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
