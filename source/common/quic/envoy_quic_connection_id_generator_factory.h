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

/**
 * Context created during configuration load and shared by the connection ID generator factories
 * created from it.
 */
class EnvoyQuicConnectionIdGeneratorContext {
public:
  virtual ~EnvoyQuicConnectionIdGeneratorContext() = default;

  /**
   * Create a connection ID generator factory. Called after the listen sockets are created.
   * @param listen_socket_factory the reuseport group's listen socket factory. Implementations
   *        may use it to access the group's sockets and inherited state (e.g. the reuseport
   *        eBPF routing program) or publish state to be shared with a hot restart child.
   */
  virtual EnvoyQuicConnectionIdGeneratorFactoryPtr
  createQuicConnectionIdGeneratorFactory(Network::ListenSocketFactory& listen_socket_factory) PURE;
};

using EnvoyQuicConnectionIdGeneratorContextPtr =
    std::unique_ptr<EnvoyQuicConnectionIdGeneratorContext>;

class EnvoyQuicConnectionIdGeneratorConfigFactory : public Config::TypedFactory {
public:
  std::string category() const override { return "envoy.quic.connection_id_generator"; }

  /**
   * @returns true if this connection id generator provides stable packet routing across hot-restart
   * epochs and LDS listener swaps, false otherwise.
   */
  virtual bool isStateful() const PURE;

  /**
   * Returns a connection ID generator context based on the given config.
   */
  virtual EnvoyQuicConnectionIdGeneratorContextPtr
  createQuicConnectionIdGeneratorContext(const Protobuf::Message& config,
                                         ProtobufMessage::ValidationVisitor& validation_visitor,
                                         Server::Configuration::FactoryContext& context) PURE;
};

} // namespace Quic
} // namespace Envoy
