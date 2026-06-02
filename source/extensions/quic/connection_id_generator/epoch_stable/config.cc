#include "source/extensions/quic/connection_id_generator/epoch_stable/config.h"

#include "envoy/extensions/quic/connection_id_generator/epoch_stable/v3/epoch_stable.pb.h"
#include "envoy/extensions/quic/connection_id_generator/epoch_stable/v3/epoch_stable.pb.validate.h"

#include "source/extensions/quic/connection_id_generator/epoch_stable/epoch_stable.h"

namespace Envoy {
namespace Quic {
namespace Extensions {
namespace ConnectionIdGenerator {
namespace EpochStable {

ProtobufTypes::MessagePtr ConfigFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::quic::connection_id_generator::epoch_stable::v3::Config>();
}

EnvoyQuicConnectionIdGeneratorFactoryPtr ConfigFactory::createQuicConnectionIdGeneratorFactory(
    const Protobuf::Message& proto_message, ProtobufMessage::ValidationVisitor& validation_visitor,
    Server::Configuration::FactoryContext&) {
  const auto& proto_config = MessageUtil::downcastAndValidate<
      const envoy::extensions::quic::connection_id_generator::epoch_stable::v3::Config&>(
      proto_message, validation_visitor);

  EpochStableConfig config(PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto_config, max_map_entries, 65536));

  auto factory_or_status = Factory::create(config);
  THROW_IF_NOT_OK_REF(factory_or_status.status());
  return std::move(factory_or_status.value());
}

REGISTER_FACTORY(ConfigFactory, EnvoyQuicConnectionIdGeneratorConfigFactory);

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
