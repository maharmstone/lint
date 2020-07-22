cmake_minimum_required(VERSION 3.10)

project(pam_muw)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(SRC_FILES
	src/pam_muw.cpp
	src/muw.cpp)

add_library(pam_muw SHARED ${SRC_FILES})

find_package(fmt REQUIRED)

set_target_properties(pam_muw PROPERTIES PREFIX "")

target_link_libraries(pam_muw muw)
target_link_libraries(pam_muw fmt::fmt-header-only)

target_compile_options(pam_muw PUBLIC -fshort-wchar)
target_compile_options(pam_muw PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
