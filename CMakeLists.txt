cmake_minimum_required(VERSION 3.28)
project(krypta)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Включаем все исходные файлы рекурсивно
file(GLOB_RECURSE SOURCES
        "src/*.cpp"
        "src/*.h"
        "src/*.hpp"
)

# Включаем заголовочные файлы из всех поддиректорий src
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/DEAL)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/DES)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/RSA)

# Основное исполняемое приложение
add_executable(main main.cpp ${SOURCES})

# Тестовое исполняемое приложение
add_executable(file_testing file_testing.cpp ${SOURCES})

# Группировка исходных файлов в IDE (Visual Studio, CLion и т.д.)
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.20)
    source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})
endif()