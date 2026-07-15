#include "source/extensions/quic/connection_id_generator/epoch_stable/config.h"

#include "envoy/common/exception.h"
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

EnvoyQuicConnectionIdGeneratorContextPtr ConfigFactory::createQuicConnectionIdGeneratorContext(
    const Protobuf::Message& proto_message, ProtobufMessage::ValidationVisitor& validation_visitor,
    Server::Configuration::FactoryContext& context) {
  MessageUtil::downcastAndValidate<
      const envoy::extensions::quic::connection_id_generator::epoch_stable::v3::Config&>(
      proto_message, validation_visitor);

  auto context_or_status = Context::create(context);
  THROW_IF_NOT_OK_REF(context_or_status.status());
  return std::move(context_or_status.value());
}

REGISTER_FACTORY(ConfigFactory, EnvoyQuicConnectionIdGeneratorConfigFactory);

} // namespace EpochStable
} // namespace ConnectionIdGenerator
} // namespace Extensions
} // namespace Quic
} // namespace Envoy
