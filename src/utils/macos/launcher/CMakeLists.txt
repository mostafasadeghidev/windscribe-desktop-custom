cmake_minimum_required(VERSION 3.23)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(launcher_mac)

if(DEV_MODE AND DEFINED ENV{PRIVATE_TEST_CODESIGN_IDENTITY} AND NOT "$ENV{PRIVATE_TEST_CODESIGN_IDENTITY}" STREQUAL "")
    set(WS_MAC_CODESIGN_IDENTITY "$ENV{PRIVATE_TEST_CODESIGN_IDENTITY}")
    set(WS_MAC_CODESIGN_TIMESTAMP_OPTION --timestamp=none)
else()
    set(WS_MAC_CODESIGN_IDENTITY "Developer ID Application")
    set(WS_MAC_CODESIGN_TIMESTAMP_OPTION --timestamp)
endif()

set(SOURCES
    appdelegate.h
    main.m
    appdelegate.mm
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/info.plist
    ${CMAKE_CURRENT_BINARY_DIR}/info.plist.configured
    @ONLY
)

add_executable(${WS_MAC_LAUNCHER_TARGET} MACOSX_BUNDLE ${SOURCES})

target_link_libraries(${WS_MAC_LAUNCHER_TARGET}
                      PRIVATE
                      "-framework AppKit"
)

set_target_properties(${WS_MAC_LAUNCHER_TARGET}
                      PROPERTIES
                      MACOSX_BUNDLE TRUE
                      MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_BINARY_DIR}/info.plist.configured
)
target_include_directories(${WS_MAC_LAUNCHER_TARGET} PRIVATE
                           ../../../client/client-common
)

# Sign launcher immediately after building
add_custom_command(TARGET ${WS_MAC_LAUNCHER_TARGET} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Signing ${WS_MAC_LAUNCHER_TARGET}..."
    COMMAND ${CODESIGN_EXECUTABLE}
            --force
            --options runtime
            ${WS_MAC_CODESIGN_TIMESTAMP_OPTION}
            --entitlements "${CMAKE_CURRENT_SOURCE_DIR}/launcher.entitlements"
            --sign "${WS_MAC_CODESIGN_IDENTITY}"
            $<TARGET_BUNDLE_DIR:${WS_MAC_LAUNCHER_TARGET}>
    COMMAND ${CODESIGN_EXECUTABLE} -v $<TARGET_BUNDLE_DIR:${WS_MAC_LAUNCHER_TARGET}>
)

