cmake_minimum_required(VERSION 3.16)
project(deltachat LANGUAGES C)
include(GNUInstallDirs)

option(WITH_JSONRPC_BINDINGS "Generate jsonrpc bindings" OFF)

find_program(CARGO cargo)

if(APPLE)
  set(DYNAMIC_EXT "dylib")
elseif(UNIX)
  set(DYNAMIC_EXT "so")
else()
  set(DYNAMIC_EXT "dll")
endif()

if(DEFINED ENV{CARGO_BUILD_TARGET})
  set(CARGO_OUT_DIR "${CMAKE_BINARY_DIR}/target/$ENV{CARGO_BUILD_TARGET}/release")
else()
  set(CARGO_OUT_DIR "${CMAKE_BINARY_DIR}/target/release")
endif()

if(WITH_JSONRPC_BINDINGS)
  set(JSONRPC_ARGS --package deltachat-jsonrpc-bindings)
endif()

add_custom_target(
  lib_deltachat
  ALL
  COMMAND
    ${CMAKE_COMMAND} -E env
    CARGO_TARGET_DIR="${CMAKE_BINARY_DIR}/target"
    PREFIX="${CMAKE_INSTALL_PREFIX}"
    LIBDIR="${CMAKE_INSTALL_FULL_LIBDIR}"
    INCLUDEDIR="${CMAKE_INSTALL_FULL_INCLUDEDIR}"
    ${CARGO} build --release --package deltachat_ffi ${JSONRPC_ARGS}
  WORKING_DIRECTORY
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

install(FILES "deltachat-ffi/deltachat.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES "${CARGO_OUT_DIR}/libdeltachat.a" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${CARGO_OUT_DIR}/libdeltachat.${DYNAMIC_EXT}" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${CARGO_OUT_DIR}/pkgconfig/deltachat.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

if(WITH_JSONRPC_BINDINGS)
  set(JSONRPC_HPP "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/deltachat-jsonrpc")
  install(FILES "${JSONRPC_HPP}/generated/types.hpp" "${JSONRPC_HPP}/generated/client.hpp"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/deltachat-jsonrpc/generated")
  install(FILES "${JSONRPC_HPP}/cffi_client.hpp"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/deltachat-jsonrpc")
endif()
