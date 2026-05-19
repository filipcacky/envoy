load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_foreign_cc//foreign_cc:make.bzl", "make")

filegroup(
    name = "all",
    srcs = glob(["**"]),
)

make(
    name = "libbpf_build",
    args = [
        "-C",
        "src",
        "BUILD_STATIC_ONLY=1",
        "NO_PKG_CONFIG=1",
        "PREFIX=$$INSTALLDIR$$",
        "LIBSUBDIR=lib",
    ],
    lib_source = ":all",
    out_static_libs = ["libbpf.a"],
    tags = ["skip_on_windows"],
    targets = ["install"],
    deps = [
        "@elfutils//:libelf",
        "@envoy//bazel:zlib",
    ],
)

cc_library(
    name = "libbpf",
    tags = ["skip_on_windows"],
    visibility = ["//visibility:public"],
    deps = [":libbpf_build"],
)
