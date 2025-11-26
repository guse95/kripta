cmake_minimum_required(VERSION 3.28)
project(krypta)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB SOURCES "src/*.cpp" "src/*.hpp" "src/*.h")

add_executable(main main.cpp ${SOURCES})
add_executable(file_testing file_testing.cpp ${SOURCES})

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.20)
    source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})
endif()