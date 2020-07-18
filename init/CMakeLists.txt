cmake_minimum_required(VERSION 3.10)

project(muwine-init)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(SRC_FILES
	init.cpp)

add_executable(muwine-init ${SRC_FILES})

find_package(fmt REQUIRED)

target_link_libraries(muwine-init muw)
target_link_libraries(muwine-init fmt::fmt-header-only)

target_compile_options(muwine-init PUBLIC -fshort-wchar)
target_compile_options(muwine-init PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
