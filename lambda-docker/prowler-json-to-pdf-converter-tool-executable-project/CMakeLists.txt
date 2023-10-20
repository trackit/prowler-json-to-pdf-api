cmake_minimum_required(VERSION 3.10)
project(prowler-to-text-report LANGUAGES CXX)

add_executable(prowler-to-text-report src/main.cpp)
target_compile_features(prowler-to-text-report PRIVATE cxx_std_17)

# fmt library
add_subdirectory(external/fmt)
target_link_libraries(prowler-to-text-report fmt::fmt)

# nlohmann library
target_include_directories(prowler-to-text-report PRIVATE "${CMAKE_SOURCE_DIR}/external/nlohmann/include")
