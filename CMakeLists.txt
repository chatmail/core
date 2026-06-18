cmake_minimum_required(VERSION 3.16)
project(deltachat LANGUAGES C)
include(GNUInstallDirs)

option(BUILD_JSONRPC_BINDINGS "Build jsonrpc bindings" OFF)

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

set(CARGO_BUILD ${CMAKE_COMMAND}
  -E env
    CARGO_TARGET_DIR="${CMAKE_BINARY_DIR}/target"
    PREFIX="${CMAKE_INSTALL_PREFIX}"
    LIBDIR="${CMAKE_INSTALL_FULL_LIBDIR}"
    INCLUDEDIR="${CMAKE_INSTALL_FULL_INCLUDEDIR}"
  ${CARGO} build --release
)

add_custom_target(
  lib_deltachat
  ALL
  COMMAND
    ${CARGO_BUILD} --package deltachat_ffi
  WORKING_DIRECTORY
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

install(FILES "deltachat-ffi/deltachat.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES "${CARGO_OUT_DIR}/libdeltachat.a" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${CARGO_OUT_DIR}/libdeltachat.${DYNAMIC_EXT}" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${CARGO_OUT_DIR}/pkgconfig/deltachat.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")


if(BUILD_JSONRPC_BINDINGS)
  add_custom_target(
    jsonrpc_bindings
    ALL
    COMMAND
      ${CARGO_BUILD} --package deltachat-jsonrpc-bindings
    WORKING_DIRECTORY
      "${CMAKE_CURRENT_SOURCE_DIR}"
  )

  install(
    FILES
      "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/types.hpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/client.hpp"
      "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/transport.hpp"
    DESTINATION
      "${CMAKE_INSTALL_INCLUDEDIR}/deltachat-jsonrpc"
    COMPONENT
      jsonrpc_bindings
  )
endif()
