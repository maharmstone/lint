cmake_minimum_required(VERSION 3.10)

project(pam_muw)

set(CMAKE_C_VISIBILITY_PRESET hidden)

set(SRC_FILES
	src/pam_muw.c)

add_library(pam_muw SHARED ${SRC_FILES})

set_target_properties(pam_muw PROPERTIES PREFIX "")

target_compile_options(pam_muw PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
