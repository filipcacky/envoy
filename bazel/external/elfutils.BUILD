load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")

cc_library(
    name = "libelf",
    tags = ["skip_on_windows"],
    visibility = ["//visibility:public"],
    deps = [":libelf_build"],
)

filegroup(
    name = "all",
    srcs = glob(["**"]),
)

configure_make(
    name = "libelf_build",
    configure_in_place = True,
    configure_options = [
        "--disable-debuginfod",
        "--disable-libdebuginfod",
        "--disable-demangler",
        "--without-lzma",
        "--without-bzlib",
        "--without-zstd",
    ],
    data = [
        "@envoy//bazel/external:zlib_archive",
    ],
    env = {
        "LDFLAGS": " ".join([
            "-L$$EXT_BUILD_ROOT$$/$(BINDIR)/bazel/external/lib",
            "-L$$EXT_BUILD_ROOT$$/$(BINDIR)/external/envoy/bazel/external/lib",
        ]),
    },
    lib_source = ":all",
    out_static_libs = [
        "libelf.a",
        "libeu.a",
    ],
    postfix_script = "cp $$BUILD_TMPDIR/lib/libeu.a $$INSTALLDIR/lib/",
    targets = [
        "-C lib",
        "-C libelf",
        "-C libelf install",
    ],
    tags = ["skip_on_windows"],
    visibility = ["//visibility:public"],
    deps = ["@envoy//bazel:zlib"],
)

exports_files(
    [
        "libelf/libelf.h",
        "libelf/elf.h",
        "libelf/gelf.h",
    ],
    visibility = ["//visibility:public"],
)
