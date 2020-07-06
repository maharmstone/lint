cmake_minimum_required(VERSION 3.10)

project(regtest)

set(SRC_FILES
	regtest.c)

add_executable(regtest ${SRC_FILES})

# add_definitions(-D_WIN32_WINNT=0x0600)

if(WIN32)
    target_link_libraries(regtest ntdll)
endif()

if(NOT WIN32)
    target_compile_options(regtest PUBLIC -fshort-wchar)
endif()

if(NOT MSVC)
	target_compile_options(regtest PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)
endif()
