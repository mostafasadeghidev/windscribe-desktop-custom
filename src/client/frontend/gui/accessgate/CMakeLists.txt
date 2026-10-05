find_package(OpenSSL REQUIRED)

target_sources(gui PRIVATE
    accessgate.cpp
    accessgate.h
    accessgateconfig.h
    securestorage.cpp
    securestorage.h
)

target_link_libraries(gui PRIVATE OpenSSL::Crypto)
if(APPLE)
    target_link_libraries(gui PRIVATE "-framework Security")
elseif(UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(GATE_LIBSECRET REQUIRED IMPORTED_TARGET GLOBAL libsecret-1)
    target_link_libraries(gui PRIVATE PkgConfig::GATE_LIBSECRET)
endif()
