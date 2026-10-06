cmake_minimum_required(VERSION 3.15)
project(splittunnelextension)

if(DEV_MODE AND DEFINED ENV{PRIVATE_TEST_CODESIGN_IDENTITY} AND NOT "$ENV{PRIVATE_TEST_CODESIGN_IDENTITY}" STREQUAL "")
    set(WS_MAC_CODESIGN_IDENTITY "$ENV{PRIVATE_TEST_CODESIGN_IDENTITY}")
    set(WS_MAC_CODESIGN_TIMESTAMP_OPTION --timestamp=none)
else()
    set(WS_MAC_CODESIGN_IDENTITY "Developer ID Application")
    set(WS_MAC_CODESIGN_TIMESTAMP_OPTION --timestamp)
endif()

find_package(c-ares REQUIRED)
find_package(spdlog CONFIG REQUIRED)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist
    ${CMAKE_CURRENT_BINARY_DIR}/Info.plist.configured
    @ONLY
)

# Create the system extension target
add_executable(${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID} MACOSX_BUNDLE
    FlowTCP.mm
    FlowUDP.mm
    ip_hostnames/ares_library_init.cpp
    ip_hostnames/dns_resolver.cpp
    ip_hostnames/ip_hostnames_manager.cpp
    main.mm
    Settings.mm
    TransparentProxyProvider.mm
    Utils.mm
)

set_target_properties(${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID} PROPERTIES
    BUNDLE TRUE
    BUNDLE_EXTENSION "systemextension"
    MACOSX_BUNDLE TRUE
    MACOSX_BUNDLE_GUI_IDENTIFIER "${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID}"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_BINARY_DIR}/Info.plist.configured"
)

# Link against required frameworks and libraries
target_link_libraries(${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID} PRIVATE
    "-framework NetworkExtension"
    "-framework Foundation"
    "-framework Network"
    "-framework Security"
    "-sectcreate __TEXT __info_plist ${CMAKE_CURRENT_BINARY_DIR}/Info.plist.configured"
    spdlog::spdlog
    c-ares::cares
)

# Configure entitlements with DEVELOPMENT_TEAM substitution
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/splittunnelextension.entitlements
    ${CMAKE_CURRENT_BINARY_DIR}/splittunnelextension.entitlements.configured
    @ONLY
)

# Copy provisioning profile first (if it exists)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../data/provisioning_profile/splittunnelextension.provisionprofile")
    add_custom_command(TARGET ${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/../../../data/provisioning_profile/splittunnelextension.provisionprofile"
            $<TARGET_FILE_DIR:${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID}>/../embedded.provisionprofile
    )
endif()

# Sign split tunnel extension immediately after building
add_custom_command(TARGET ${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Signing split tunnel extension..."
    COMMAND ${CODESIGN_EXECUTABLE}
            --force
            --options runtime
            ${WS_MAC_CODESIGN_TIMESTAMP_OPTION}
            --entitlements "${CMAKE_CURRENT_BINARY_DIR}/splittunnelextension.entitlements.configured"
            --sign "${WS_MAC_CODESIGN_IDENTITY}"
            $<TARGET_BUNDLE_DIR:${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID}>
    COMMAND ${CODESIGN_EXECUTABLE} -v $<TARGET_BUNDLE_DIR:${WS_MAC_SPLIT_TUNNEL_BUNDLE_ID}>
)
