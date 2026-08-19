#include <ostream>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/json/json_internal.h"
#include "source/common/json/json_streamer.h"

#include "absl/strings/str_format.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Json {
namespace {

template <class OutputType> class BufferOutputWrapper {
public:
  using Type = OutputType;
  std::string toString() { return underlying_buffer_.toString(); }
  void clear() { underlying_buffer_.drain(underlying_buffer_.length()); }
  Buffer::OwnedImpl underlying_buffer_;
};

class StringOutputWrapper {
public:
  using Type = StringOutput;
  std::string toString() { return underlying_buffer_; }
  void clear() { underlying_buffer_.clear(); }
  std::string underlying_buffer_;
};

template <typename T> class JsonStreamerTest : public testing::Test {
public:
  std::string toString() {
    streamer_.flush();
    return buffer_.toString();
  }

  T buffer_;
  Json::StreamerBase<typename T::Type> streamer_{this->buffer_.underlying_buffer_};
};

using OutputBufferTypes = ::testing::Types<BufferOutputWrapper<BufferOutput>,
                                           BufferOutputWrapper<BufferedBufferOutput>,
                                           StringOutputWrapper>;
TYPED_TEST_SUITE(JsonStreamerTest, OutputBufferTypes);

TYPED_TEST(JsonStreamerTest, Empty) { EXPECT_EQ("", this->toString()); }

TYPED_TEST(JsonStreamerTest, EmptyMap) {
  this->streamer_.makeRootMap();
  EXPECT_EQ("{}", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapOneDouble) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addEntries({{"a", 3.141592654}});
  }
  EXPECT_EQ(R"EOF({"a":3.141592654})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapTwoDoubles) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addEntries({{"a", -989282.1087}, {"b", 1.23456789012345e+67}});
  }
  EXPECT_EQ(R"EOF({"a":-989282.1087,"b":1.23456789012345e+67})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapOneUInt) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addEntries({{"a", static_cast<uint64_t>(0xffffffffffffffff)}});
  }
  EXPECT_EQ(R"EOF({"a":18446744073709551615})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapTwoInts) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addEntries({{"a", static_cast<int64_t>(0x7fffffffffffffff)},
                     {"b", static_cast<int64_t>(0x8000000000000000)}});
  }
  EXPECT_EQ(R"EOF({"a":9223372036854775807,"b":-9223372036854775808})EOF",
            this->toString());
}

TYPED_TEST(JsonStreamerTest, MapOneString) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addEntries({{"a", "b"}});
  }
  EXPECT_EQ(R"EOF({"a":"b"})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapOneBool) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addEntries({{"a", true}});
  }
  EXPECT_EQ(R"EOF({"a":true})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapNonDefaultEntries) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addNonDefaultEntries({{"string", "a"},
                               {"double", 1.5},
                               {"uint", static_cast<uint64_t>(1)},
                               {"int", static_cast<int64_t>(-1)},
                               {"bool", true}});
  }
  EXPECT_EQ(R"EOF({"string":"a","double":1.5,"uint":1,"int":-1,"bool":true})EOF",
            this->buffer_.toString());
}

TYPED_TEST(JsonStreamerTest, MapNonDefaultEntriesLeavesOutDefaults) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addNonDefaultEntries({{"string", ""},
                               {"double", 0.0},
                               {"uint", static_cast<uint64_t>(0)},
                               {"int", static_cast<int64_t>(0)},
                               {"bool", false},
                               {"nothing", absl::monostate()},
                               {"kept", "a"}});
  }
  EXPECT_EQ(R"EOF({"kept":"a"})EOF", this->buffer_.toString());
}

TYPED_TEST(JsonStreamerTest, MapTwoBools) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addEntries({{"a", true}, {"b", false}});
  }
  EXPECT_EQ(R"EOF({"a":true,"b":false})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapOneSanitized) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addKey("a");
    map->addString("\b\001");
  }
  EXPECT_EQ(R"EOF({"a":"\b\u0001"})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapTwoSanitized) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addKey("a");
    map->addString("\b\001");
    map->addKey("b");
    map->addString("\r\002");
  }
  EXPECT_EQ(R"EOF({"a":"\b\u0001","b":"\r\u0002"})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, SubArray) {
  auto map = this->streamer_.makeRootMap();
  map->addKey("a");
  auto array = map->addArray();
  array->addEntries({1.0, "two", 3.5, true, false, std::nan("")});
  array.reset();
  map->addEntries({{"embedded\"quote", "value"}});
  map.reset();
  EXPECT_EQ(R"EOF({"a":[1,"two",3.5,true,false,null],"embedded\"quote":"value"})EOF",
            this->toString());
}

TYPED_TEST(JsonStreamerTest, TopArray) {
  {
    auto array = this->streamer_.makeRootArray();
    array->addEntries({1.0, "two", 3.5, true, false, std::nan(""), absl::monostate{}});
  }
  EXPECT_EQ(R"EOF([1,"two",3.5,true,false,null,null])EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, SubMap) {
  auto map = this->streamer_.makeRootMap();
  map->addKey("a");
  auto sub_map = map->addMap();
  sub_map->addEntries({{"one", 1.0}, {"three.5", 3.5}});
  sub_map.reset();
  map.reset();
  EXPECT_EQ(R"EOF({"a":{"one":1,"three.5":3.5}})EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, MapRawJson) {
  {
    auto map = this->streamer_.makeRootMap();
    map->addKey("nested");
    map->addRawJson(R"({"inner":"value","num":42})");
    map->addKey("after");
    map->addString("test");
  }
  EXPECT_EQ(R"EOF({"nested":{"inner":"value","num":42},"after":"test"})EOF",
            this->toString());
}

TYPED_TEST(JsonStreamerTest, ArrayRawJson) {
  {
    auto array = this->streamer_.makeRootArray();
    array->addString("first");
    array->addRawJson(R"({"embedded":"object"})");
    array->addRawJson(R"([1,2,3])");
    array->addNumber(static_cast<int64_t>(99));
  }
  EXPECT_EQ(R"EOF(["first",{"embedded":"object"},[1,2,3],99])EOF", this->toString());
}

TYPED_TEST(JsonStreamerTest, SimpleDirectCall) {
  {
    this->streamer_.addBool(true);
    EXPECT_EQ("true", this->toString());
    this->buffer_.clear();
  }

  {
    this->streamer_.addBool(false);
    EXPECT_EQ("false", this->toString());
    this->buffer_.clear();
  }

  {
    this->streamer_.addString("hello");
    EXPECT_EQ(R"EOF("hello")EOF", this->toString());
    this->buffer_.clear();
  }

  {
    uint64_t value = 1;
    this->streamer_.addNumber(value);
    EXPECT_EQ("1", this->toString());
    this->buffer_.clear();
  }

  {
    this->streamer_.addNumber(1.5);
    EXPECT_EQ("1.5", this->toString());
    this->buffer_.clear();
  }

  {
    this->streamer_.addNull();
    EXPECT_EQ("null", this->toString());
    this->buffer_.clear();
  }
}

} // namespace
} // namespace Json
} // namespace Envoy
