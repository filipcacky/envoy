load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
    "envoy_select_enable_http3",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "epoch_stable_test",
    srcs = envoy_select_enable_http3(["epoch_stable_test.cc"]),
    extension_names = ["envoy.quic.connection_id_generator.epoch_stable"],
    rbe_pool = "6gig",
    tags = ["skip_on_windows"],
    deps = envoy_select_enable_http3([
        "//source/common/buffer:buffer_lib",
        "//source/common/network:bpf_syscalls_lib",
        "//source/extensions/quic/connection_id_generator/epoch_stable:epoch_stable_lib",
        "//test/mocks/network:network_mocks",
        "//test/test_common:status_utility_lib",
        "//test/test_common:threadsafe_singleton_injector_lib",
        "@quiche//:quic_test_tools_test_utils_lib",
    ]),
)
