cmake_minimum_required(VERSION 3.16)

project(minisiem_cpp VERSION 1.0 LANGUAGES CXX)

include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library(minisiem_core src/minisiem.cpp)
target_include_directories(minisiem_core PUBLIC include)
target_compile_features(minisiem_core PUBLIC cxx_std_17)

add_executable(minisiem src/main.cpp)
target_link_libraries(minisiem PRIVATE minisiem_core)

add_executable(minisiem_tests tests/test_minisiem.cpp)
target_link_libraries(minisiem_tests PRIVATE minisiem_core GTest::gtest_main)

if(MSVC)
    target_compile_options(minisiem_core PRIVATE /W4)
    target_compile_options(minisiem PRIVATE /W4)
    target_compile_options(minisiem_tests PRIVATE /W4)
else()
    target_compile_options(minisiem_core PRIVATE -Wall -Wextra -pedantic)
    target_compile_options(minisiem PRIVATE -Wall -Wextra -pedantic)
    target_compile_options(minisiem_tests PRIVATE -Wall -Wextra -pedantic)
endif()

enable_testing()
include(GoogleTest)
gtest_discover_tests(minisiem_tests)
