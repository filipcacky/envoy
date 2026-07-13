#pragma once

#include "envoy/config/typed_config.h"
#include "envoy/network/listener.h"
#include "envoy/network/socket.h"
#include "envoy/server/factory_context.h"

#include "quiche/quic/core/connection_id_generator.h"

namespace Envoy {
namespace Quic {

using QuicConnectionIdGeneratorPtr = std::unique_ptr<quic::ConnectionIdGeneratorInterface>;
// A function similar to the BPF program from createCompatibleLinuxBpfSocketOption, it takes
// a QUIC packet and returns the appropriate worker_index.
using QuicConnectionIdWorkerSelector =
    std::function<uint32_t(const Buffer::Instance& packet, uint32_t default_value)>;

/**
 * A factory interface to provide QUIC connection IDs and compatible BPF code for stable packet
 * routing.
 */
class EnvoyQuicConnectionIdGeneratorFactory {
public:
  virtual ~EnvoyQuicConnectionIdGeneratorFactory() = default;

  /**
   * Create a connection ID generator object.
   * @param worker_index an index to be encoded to QUIC connection ID for routing packets to the
   * current listener.
   */
  virtual QuicConnectionIdGeneratorPtr createQuicConnectionIdGenerator(uint32_t worker_index) PURE;

  /**
   * Create a socket option with BPF program to consistently route QUIC packets to the right listen
   * socket. Linux only, absl::UnimplementedError on other platforms.
   * @returns the socket option or an error status.
   */
  virtual absl::StatusOr<Network::Socket::OptionConstSharedPtr>
  createCompatibleLinuxBpfSocketOption() PURE;

  /**
   * Returns a function to retrieve the worker index associated with a QUIC packet; the same
   * principle as the BPF program above, but for contexts where BPF is unavailable.
   */
  virtual QuicConnectionIdWorkerSelector getCompatibleConnectionIdWorkerSelector() PURE;
};

using EnvoyQuicConnectionIdGeneratorFactoryPtr =
    std::unique_ptr<EnvoyQuicConnectionIdGeneratorFactory>;

class EnvoyQuicConnectionIdGeneratorConfigFactory : public Config::TypedFactory {
public:
  std::string category() const override { return "envoy.quic.connection_id_generator"; }

  /**
   * @returns true if this connection id generator provides stable packet routing across hot-restart
   * epochs and LDS listener swaps, false otherwise.
   */
  virtual bool isStateful() const PURE;

  /**
   * Returns a connection ID factory based on the given config.
   */
  virtual EnvoyQuicConnectionIdGeneratorFactoryPtr
  createQuicConnectionIdGeneratorFactory(const Protobuf::Message& config,
                                         Server::Configuration::FactoryContext& context) PURE;

  /**
   * Returns a connection ID factory based on the given config.
   */
  virtual EnvoyQuicConnectionIdGeneratorFactoryPtr
  createQuicConnectionIdGeneratorFactoryForReuseportGroup(
      const Protobuf::Message& config, Server::Configuration::FactoryContext& context,
      Network::ListenSocketFactory& listen_socket_factory) PURE;
};

} // namespace Quic
} // namespace Envoy
