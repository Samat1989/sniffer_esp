# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# Prefer release tag as firmware version (e.g. v1.0.15 -> 1.0.15).
# Fallback to git describe for local/dev builds.
set(_sniffer_ver "")
if(DEFINED ENV{GITHUB_REF_TYPE} AND "$ENV{GITHUB_REF_TYPE}" STREQUAL "tag")
    set(_sniffer_ver "$ENV{GITHUB_REF_NAME}")
endif()

if(_sniffer_ver STREQUAL "" AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
    execute_process(
        COMMAND git describe --tags --always --dirty
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE _sniffer_git_describe
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT _sniffer_git_describe STREQUAL "")
        set(_sniffer_ver "${_sniffer_git_describe}")
    endif()
endif()

if(_sniffer_ver STREQUAL "")
    set(_sniffer_ver "0.0.0-local")
endif()

string(REGEX REPLACE "^v" "" PROJECT_VER "${_sniffer_ver}")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(sniffer_esp)
