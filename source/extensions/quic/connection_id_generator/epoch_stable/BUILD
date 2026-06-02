load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
    "envoy_select_enable_http3",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

genrule(
    name = "route_bpf_obj",
    srcs = [
        "route.c",
        "routing_config.h",
        "@libbpf//:all",
    ],
    outs = ["route.bpf.o"],
    cmd = "LIBBPF_SRC=$$(dirname $$(echo $(locations @libbpf//:all) | tr ' ' '\\n' | grep 'src/bpf_helpers.h'))/.. && " +
          "clang -target bpf -O2 -g -isystem /usr/include/$$(uname -m)-linux-gnu -I$$(dirname $(location route.c)) -I$$LIBBPF_SRC/src -I$$LIBBPF_SRC/include/uapi -c $(location route.c) -o $@",
    target_compatible_with = ["@platforms//os:linux"],
)

genrule(
    name = "route_bpf_embed",
    srcs = [":route_bpf_obj"],
    outs = ["route_bpf_embedded.h"],
    cmd = "( echo 'static const unsigned char route_bpf_data[] = {' && xxd -i < $(SRCS) && echo '};' && echo 'static const unsigned int route_bpf_data_len = sizeof(route_bpf_data);' ) > $@",
    target_compatible_with = ["@platforms//os:linux"],
)

envoy_cc_library(
    name = "epoch_stable_lib",
    srcs = envoy_select_enable_http3(["epoch_stable.cc"]),
    hdrs = envoy_select_enable_http3(["epoch_stable.h"]) + select({
        "//bazel:linux": [
            "route_bpf_embedded.h",
            "routing_config.h",
        ],
        "//conditions:default": [],
    }),
    tags = ["skip_on_windows"],
    deps = envoy_select_enable_http3([
        "//source/common/network:socket_option_lib",
        "@quiche//:quic_core_deterministic_connection_id_generator_lib",
        "//source/common/quic:envoy_quic_connection_id_generator_factory_interface",
        "@envoy_api//envoy/extensions/quic/connection_id_generator/epoch_stable/v3:pkg_cc_proto",
    ]) + select({
        "//bazel:linux": ["@libbpf//:libbpf"],
        "//conditions:default": [],
    }),
)

envoy_cc_library(
    name = "config_lib",
    srcs = envoy_select_enable_http3(["config.cc"]),
    hdrs = envoy_select_enable_http3(["config.h"]),
    tags = ["skip_on_windows"],
    deps = envoy_select_enable_http3([
        ":epoch_stable_lib",
        "//envoy/registry",
        "//source/common/quic:envoy_quic_connection_id_generator_factory_interface",
        "@envoy_api//envoy/extensions/quic/connection_id_generator/epoch_stable/v3:pkg_cc_proto",
    ]),
)

envoy_cc_extension(
    name = "epoch_stable_config",
    tags = ["skip_on_windows"],
    deps = envoy_select_enable_http3([
        ":config_lib",
    ]),
)
