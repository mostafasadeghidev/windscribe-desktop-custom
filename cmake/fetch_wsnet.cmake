if(NOT TARGET wsnet::wsnet)
    include(FetchContent)
    FetchContent_Declare(wsnet
        GIT_REPOSITORY https://github.com/Windscribe/wsnet.git
        GIT_TAG        1.5.43
        PATCH_COMMAND  ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_LIST_DIR}/patch_wsnet.cmake
    )
    set(IS_BUILD_TESTS OFF)
    FetchContent_MakeAvailable(wsnet)
endif()
