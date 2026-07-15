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
  EnvoyQuicConnectionIdGeneratorFactoryPtr
  createQuicConnectionIdGeneratorFactory(const Protobuf::Message& config,
                                         ProtobufMessage::ValidationVisitor& validation_visitor,
                                         Server::Configuration::FactoryContext& context) override;
  absl::StatusOr<EnvoyQuicConnectionIdGeneratorFactoryPtr>
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
