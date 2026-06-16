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

add_custom_command(
	OUTPUT
	"${CMAKE_BINARY_DIR}/target/release/libdeltachat.a"
	"${CMAKE_BINARY_DIR}/target/release/libdeltachat.${DYNAMIC_EXT}"
	"${CMAKE_BINARY_DIR}/target/release/pkgconfig/deltachat.pc"
        COMMAND
        PREFIX=${CMAKE_INSTALL_PREFIX}
        LIBDIR=${CMAKE_INSTALL_FULL_LIBDIR}
        INCLUDEDIR=${CMAKE_INSTALL_FULL_INCLUDEDIR}
	${CARGO} build --target-dir=${CMAKE_BINARY_DIR}/target --release
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deltachat-ffi
)

add_custom_target(
	lib_deltachat
	ALL
	DEPENDS
	"${CMAKE_BINARY_DIR}/target/release/libdeltachat.a"
	"${CMAKE_BINARY_DIR}/target/release/libdeltachat.${DYNAMIC_EXT}"
	"${CMAKE_BINARY_DIR}/target/release/pkgconfig/deltachat.pc"
)

add_custom_command(
    OUTPUT
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/types.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/client.hpp"
    COMMAND
    PREFIX=${CMAKE_INSTALL_PREFIX}
    LIBDIR=${CMAKE_INSTALL_FULL_LIBDIR}
    INCLUDEDIR=${CMAKE_INSTALL_FULL_INCLUDEDIR}
    ${CARGO} build --target-dir=${CMAKE_BINARY_DIR}/target --release
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings
)

add_custom_target(
    rpc_headers
    DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/types.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/client.hpp"
)

install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/types.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/generated/client.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/deltachat-jsonrpc-bindings/qt/transport.hpp"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/deltachat-jsonrpc
)

install(FILES "deltachat-ffi/deltachat.h" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES "${CMAKE_BINARY_DIR}/target/${ARCH_DIR}/release/libdeltachat.a" DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES "${CMAKE_BINARY_DIR}/target/${ARCH_DIR}/release/libdeltachat.${DYNAMIC_EXT}" DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES "${CMAKE_BINARY_DIR}/target/${ARCH_DIR}/release/pkgconfig/deltachat.pc" DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
