#pragma once

#include "source/common/quic/envoy_quic_connection_id_generator_factory.h"

#include "quiche/quic/core/deterministic_connection_id_generator.h"

#if defined(__linux__)
#include <linux/filter.h>
#endif

namespace Envoy {
namespace Quic {

// This class modifies connection ids that are too long in an Envoy fashion.
class EnvoyDeterministicConnectionIdGenerator : public quic::DeterministicConnectionIdGenerator {

  using DeterministicConnectionIdGenerator::DeterministicConnectionIdGenerator;

public:
  // Hashes |original| to create a new connection ID in Envoy fashion.
  std::optional<quic::QuicConnectionId>
  GenerateNextConnectionId(const quic::QuicConnectionId& original) override;
  // Replace the connection ID if and only if |original| is not of the expected
  // length in Envoy fashion.
  std::optional<quic::QuicConnectionId>
  MaybeReplaceConnectionId(const quic::QuicConnectionId& original,
                           const quic::ParsedQuicVersion& version) override;
};

class EnvoyDeterministicConnectionIdGeneratorFactory
    : public EnvoyQuicConnectionIdGeneratorFactory {
public:
  explicit EnvoyDeterministicConnectionIdGeneratorFactory(uint32_t concurrency)
      : concurrency_(concurrency) {}

  // EnvoyQuicConnectionIdGeneratorFactory.
  QuicConnectionIdGeneratorPtr createQuicConnectionIdGenerator(uint32_t worker_index) override;
  absl::StatusOr<Network::Socket::OptionConstSharedPtr>
  createCompatibleLinuxBpfSocketOption() override;
  QuicConnectionIdWorkerSelector getCompatibleConnectionIdWorkerSelector() override;

private:
  const uint32_t concurrency_;
#if defined(SO_ATTACH_REUSEPORT_CBPF) && defined(__linux__)
  sock_fprog prog_;
  std::vector<sock_filter> filter_;
#endif
};

class EnvoyDeterministicConnectionIdGeneratorContext
    : public EnvoyQuicConnectionIdGeneratorContext {
public:
  explicit EnvoyDeterministicConnectionIdGeneratorContext(uint32_t concurrency)
      : concurrency_(concurrency) {}

  // EnvoyQuicConnectionIdGeneratorContext.
  EnvoyQuicConnectionIdGeneratorFactoryPtr
  createQuicConnectionIdGeneratorFactory(Network::ListenSocketFactory&) override;

private:
  const uint32_t concurrency_;
};

} // namespace Quic
} // namespace Envoy
