#include "source/extensions/filters/http/periodic_bytes/filter.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/http/header_map_impl.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PeriodicBytes {

Http::FilterHeadersStatus PeriodicBytesFilter::decodeHeaders(Http::RequestHeaderMap&, bool) {
  auto headers = Http::ResponseHeaderMapImpl::create();
  headers->setStatus(200);

  decoder_callbacks_->encodeHeaders(std::move(headers), false, "periodic_bytes");

  tick_timer_ = decoder_callbacks_->dispatcher().createTimer([this]() { onTick(); });
  tick_timer_->enableTimer(interval_);

  return Http::FilterHeadersStatus::StopIteration;
}

void PeriodicBytesFilter::onTick() {
  Buffer::OwnedImpl buf;
  buf.add(std::string(response_bytes_, 'x'));
  decoder_callbacks_->encodeData(buf, false);
  tick_timer_->enableTimer(interval_);
}

void PeriodicBytesFilter::onDestroy() {
  if (tick_timer_) {
    tick_timer_->disableTimer();
  }
}

} // namespace PeriodicBytes
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
