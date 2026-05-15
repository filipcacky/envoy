#pragma once

#include <cstdint>
#include <chrono>

#include "envoy/event/timer.h"
#include "envoy/http/filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace PeriodicBytes {

class PeriodicBytesFilter : public Http::StreamDecoderFilter {
public:
  PeriodicBytesFilter(std::chrono::milliseconds interval, uint32_t response_bytes)
      : interval_(interval), response_bytes_(response_bytes) {}

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override {
    return Http::FilterTrailersStatus::StopIteration;
  }
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override {
    decoder_callbacks_ = &callbacks;
  }

private:
  void onTick();

  const std::chrono::milliseconds interval_;
  const uint32_t response_bytes_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{};
  Event::TimerPtr tick_timer_;
};

} // namespace PeriodicBytes
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
