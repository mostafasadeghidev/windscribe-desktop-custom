# Employee build: patches applied to the fetched wsnet sources.
# Run by FetchContent's PATCH_COMMAND with the wsnet source tree as the working directory.
#
# API timeout: on filtered networks the API is reached through the company relay, often slowly, and the
# sign-in answer carries CAPTCHA images of about 60 KB. With the stock 10-second limit most attempts were
# cut off just before finishing, so allow 30 seconds per request.

set(settings_file "src/settings.h")
file(READ "${settings_file}" content)
set(stock "kApiTimeout = 10000;")
set(patched "kApiTimeout = 30000;")
string(FIND "${content}" "${patched}" already)
if(already EQUAL -1)
    string(FIND "${content}" "${stock}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "patch_wsnet: '${stock}' not found in ${settings_file}; update cmake/patch_wsnet.cmake")
    endif()
    string(REPLACE "${stock}" "${patched}" content "${content}")
    file(WRITE "${settings_file}" "${content}")
    message(STATUS "patch_wsnet: API timeout raised to 30 seconds")
endif()
