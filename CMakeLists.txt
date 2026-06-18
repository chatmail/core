cmake_minimum_required(VERSION 3.16)
project(deltachat LANGUAGES C)
include(GNUInstallDirs)

find_program(CARGO cargo)

if(APPLE)
  set(DYNAMIC_EXT "dylib")
elseif(UNIX)
  set(DYNAMIC_EXT "so")
else()
  set(DYNAMIC_EXT "dll")
endif()

if(DEFINED ENV{CARGO_BUILD_TARGET})
  set(ARCH_DIR "$ENV{CARGO_BUILD_TARGET}")
else()
  set(ARCH_DIR "./")
endif()

# Keep same env for all cargo calls to enable caching
set(CARGO_BUILD ${CMAKE_COMMAND}
  -E env
    CARGO_TARGET_DIR="${CMAKE_BINARY_DIR}/target"
    PREFIX="${CMAKE_INSTALL_PREFIX}"
    LIBDIR="${CMAKE_INSTALL_FULL_LIBDIR}"
    INCLUDEDIR="${CMAKE_INSTALL_FULL_INCLUDEDIR}"
  ${CARGO} build --release
)

set(CARGO_OUT_DIR "${CMAKE_BINARY_DIR}/target/${ARCH_DIR}/release")

add_custom_command(
  OUTPUT
    "${CARGO_OUT_DIR}/libdeltachat.a"
    "${CARGO_OUT_DIR}/libdeltachat.${DYNAMIC_EXT}"
    "${CARGO_OUT_DIR}/pkgconfig/deltachat.pc"
  COMMAND
    ${CARGO_BUILD}
  WORKING_DIRECTORY
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-ffi"
)

add_custom_target(
  lib_deltachat
  ALL
  DEPENDS
    "${CARGO_OUT_DIR}/libdeltachat.a"
    "${CARGO_OUT_DIR}/libdeltachat.${DYNAMIC_EXT}"
    "${CARGO_OUT_DIR}/pkgconfig/deltachat.pc"
)

install(FILES "deltachat-ffi/deltachat.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES "${CARGO_OUT_DIR}/libdeltachat.a" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${CARGO_OUT_DIR}/libdeltachat.${DYNAMIC_EXT}" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${CARGO_OUT_DIR}/pkgconfig/deltachat.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")


add_custom_command(
  OUTPUT
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/types.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/client.hpp"
  COMMAND
    ${CARGO_BUILD}
  WORKING_DIRECTORY
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings"
)

add_custom_target(
  deltachat_jsonrpc_bindings
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/types.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/client.hpp"
)

install(
  FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/types.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/client.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/transport.hpp"
  DESTINATION
    "${CMAKE_INSTALL_INCLUDEDIR}/deltachat-jsonrpc"
)
