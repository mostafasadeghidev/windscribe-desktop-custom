# ------------------------------------------------------------------------------
# Common Code Signing Configuration
# ------------------------------------------------------------------------------

# Common build directories
set(BUILD_EXE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/build-exe")
set(BUILD_TEMP_DIR "${CMAKE_BINARY_DIR}/temp")
set(BUILD_INSTALLER_FILES "${BUILD_TEMP_DIR}/InstallerFiles")

# ------------------------------------------------------------------------------
# Windows Signing Configuration
# ------------------------------------------------------------------------------

if(WIN32)
    set(SIGNTOOL "${CMAKE_CURRENT_SOURCE_DIR}/tools/signing/signtool.exe")
    set(SIGNING_CERT "${CMAKE_CURRENT_SOURCE_DIR}/tools/signing/code_signing.der")
    set(SIGNING_TIMESTAMP "http://timestamp.digicert.com")
    set(WINDOWS_CERT_SUBJECT_NAME "Windscribe Limited")

    set(WINDOWS_SIGN_PARAMS "/fd SHA256 /td SHA256 /tr ${SIGNING_TIMESTAMP} /f ${SIGNING_CERT} /csp \"eToken Base Cryptographic Provider\" /kc \"[{{%WINDOWS_SIGNING_TOKEN_PASSWORD%}}]=%CONTAINER_NAME%\" /n \"${WINDOWS_CERT_SUBJECT_NAME}\"")

    if(SIGN_APP OR SIGN_INSTALLER OR SIGN_BOOTSTRAP)
        if(NOT EXISTS "${SIGNTOOL}")
            message(FATAL_ERROR "signtool not found at ${SIGNTOOL}. Cannot sign.")
        endif()

        if(NOT EXISTS "${SIGNING_CERT}")
            message(FATAL_ERROR "Signing certificate not found at ${SIGNING_CERT}. Cannot sign.")
        endif()

        if(NOT DEFINED ENV{WINDOWS_SIGNING_TOKEN_PASSWORD})
            message(FATAL_ERROR "WINDOWS_SIGNING_TOKEN_PASSWORD environment variable is not set. Cannot sign.")
        endif()
    endif()

    if(SIGN_APP)
        add_custom_target(sign-app ALL)
        if(TARGET copy-app-artifacts)
            add_dependencies(sign-app copy-app-artifacts)
        endif()

        add_custom_command(TARGET sign-app
            COMMAND @for %f in (${BUILD_INSTALLER_FILES}/*.exe ${BUILD_INSTALLER_FILES}/*.dll) do @${SIGNTOOL} sign ${WINDOWS_SIGN_PARAMS} \"${BUILD_INSTALLER_FILES}/%~nxf\" >nul 2>&1
            COMMENT "Signing Windows executables and DLLs..."
        )
    endif()

    if(SIGN_INSTALLER)
        add_custom_target(sign-installer ALL)
        if(TARGET ${WS_WIN_INSTALLER_TARGET})
            add_dependencies(sign-installer ${WS_WIN_INSTALLER_TARGET})
        endif()

        add_custom_command(TARGET sign-installer
            COMMAND ${CMAKE_COMMAND} -E echo "Signing installer..."
            COMMAND ${SIGNTOOL} sign ${WINDOWS_SIGN_PARAMS} ${CMAKE_BINARY_DIR}/src/installer/${INSTALLER_TYPE}/windows/installer/${WS_WIN_INSTALLER_TARGET}.exe
        )
    endif()

    if(SIGN_BOOTSTRAP)
        add_custom_target(sign-bootstrap ALL)
        if(TARGET ${WS_WIN_BOOTSTRAP_TARGET})
            add_dependencies(sign-bootstrap ${WS_WIN_BOOTSTRAP_TARGET})
        endif()

        add_custom_command(TARGET sign-bootstrap
            COMMAND ${SIGNTOOL} sign ${WINDOWS_SIGN_PARAMS} ${CMAKE_BINARY_DIR}/src/installer/${INSTALLER_TYPE}/windows/bootstrap/${WS_PRODUCT_NAME_LOWER}_installer.exe
            COMMENT "Signing bootstrap..."
        )
    endif()
endif()

# ------------------------------------------------------------------------------
# macOS Signing Configuration
# ------------------------------------------------------------------------------

if(APPLE)
    # Extract Development Team ID from executable_signature_defs.h
    if(NOT DEFINED DEVELOPMENT_TEAM OR DEVELOPMENT_TEAM STREQUAL "")
        set(SIGNATURE_DEFS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/client/client-common/utils/executable_signature/executable_signature_defs.h")
        if(EXISTS "${SIGNATURE_DEFS_FILE}")
            file(READ "${SIGNATURE_DEFS_FILE}" SIGNATURE_DEFS)
            if(SIGNATURE_DEFS MATCHES "MACOS_CERT_TEAM_ID \"([A-Z0-9]+)\"")
                set(DEVELOPMENT_TEAM "${CMAKE_MATCH_1}" CACHE STRING "Apple Development Team ID")
                message(STATUS "Extracted DEVELOPMENT_TEAM: ${DEVELOPMENT_TEAM}")
            else()
                message(FATAL_ERROR "Could not extract DEVELOPMENT_TEAM from ${SIGNATURE_DEFS_FILE}")
            endif()
        else()
            message(FATAL_ERROR "Could not find ${SIGNATURE_DEFS_FILE}")
        endif()
    endif()

    # Find codesign utility
    find_program(CODESIGN_EXECUTABLE codesign)
    if(NOT CODESIGN_EXECUTABLE)
        message(FATAL_ERROR "codesign not found. Code signing is required on macOS.")
    endif()

    # Private DEV_MODE builds use ad-hoc signatures and identifier-only requirements so
    # the app and its SMJobBless helper can be tested without an Apple Developer ID.
    # These requirements are intentionally unsuitable for releases.
    if(DEV_MODE)
        set(WS_MAC_GUI_REQUIREMENT "identifier &quot;${WS_MAC_GUI_BUNDLE_ID}&quot;")
        set(WS_MAC_INSTALLER_REQUIREMENT "identifier &quot;${WS_MAC_INSTALLER_BUNDLE_ID}&quot;")
        set(WS_MAC_HELPER_REQUIREMENT "identifier &quot;${WS_MAC_HELPER_BUNDLE_ID}&quot;")
    else()
        set(_WS_MAC_APPLE_REQUIREMENT_PREFIX "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = ${DEVELOPMENT_TEAM}")
        set(WS_MAC_GUI_REQUIREMENT "identifier &quot;${WS_MAC_GUI_BUNDLE_ID}&quot; and ${_WS_MAC_APPLE_REQUIREMENT_PREFIX}")
        set(WS_MAC_INSTALLER_REQUIREMENT "identifier &quot;${WS_MAC_INSTALLER_BUNDLE_ID}&quot; and ${_WS_MAC_APPLE_REQUIREMENT_PREFIX}")
        set(WS_MAC_HELPER_REQUIREMENT "anchor apple generic and identifier &quot;${WS_MAC_HELPER_BUNDLE_ID}&quot; and (certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = ${DEVELOPMENT_TEAM})")
    endif()
endif()

# ------------------------------------------------------------------------------
# Linux Signing Configuration
# ------------------------------------------------------------------------------
#
# Linux package signing rides along with the SIGN_APP option (the same flag Windows uses
# to gate Authenticode signing). The actual signing logic lives in packaging_linux.cmake
# because it runs as a post-build step on each package output; this file just owns the
# Windows/macOS signing setup. See cmake/packaging_linux.cmake for the DEB / RPM hooks
# and `LINUX_SIGNING_MASTER_FINGERPRINTS` in executable_signature_defs.h for the
# compile-time trust anchor used by the helper-side verifier.
