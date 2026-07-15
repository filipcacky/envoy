#pragma once

#include "envoy/registry/registry.h"

#include "source/common/quic/envoy_quic_connection_id_generator_factory.h"

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {

class ConfigFactory : public Quic::EnvoyQuicConnectionIdGeneratorConfigFactory {
public:
  // EnvoyQuicConnectionIdGeneratorConfigFactory.
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
  bool isStateful() const override { return true; }
  Quic::EnvoyQuicConnectionIdGeneratorFactoryPtr
  createQuicConnectionIdGeneratorFactory(const Protobuf::Message& config,
                                         Server::Configuration::FactoryContext& context) override;
  Quic::EnvoyQuicConnectionIdGeneratorFactoryPtr
  createQuicConnectionIdGeneratorFactoryForReuseportGroup(
      const Protobuf::Message& proto_message, Server::Configuration::FactoryContext& context,
      Network::ListenSocketFactory& listen_socket_factory) override;
  std::string name() const override { return "envoy.quic.connection_id_generator.epoch_stable"; }
};

DECLARE_FACTORY(ConfigFactory);

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
