cmake_minimum_required(VERSION 3.10)

project(tests)

add_executable(regtest regtest.c)

if(WIN32)
    target_link_libraries(regtest ntdll)
else()
    target_link_libraries(regtest muw)
endif()

if(NOT WIN32)
    target_compile_options(regtest PUBLIC -fshort-wchar)
endif()

if(NOT MSVC)
	target_compile_options(regtest PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)
endif()

# --------------------

add_executable(filetest filetest.c)

if(WIN32)
    target_link_libraries(filetest ntdll)
else()
    target_link_libraries(filetest muw)
endif()

if(NOT WIN32)
    target_compile_options(filetest PUBLIC -fshort-wchar)
endif()

if(NOT MSVC)
	target_compile_options(filetest PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)
endif()

# --------------------

add_executable(threadtest threadtest.c)

if(WIN32)
    target_link_libraries(threadtest ntdll)
else()
    target_link_libraries(threadtest muw)
endif()

if(NOT WIN32)
    target_compile_options(threadtest PUBLIC -fshort-wchar)
endif()

if(NOT MSVC)
	target_compile_options(threadtest PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)
endif()

# --------------------

add_executable(proctest proctest.c)

if(WIN32)
    target_link_libraries(proctest ntdll)
else()
    target_link_libraries(proctest muw)
endif()

if(NOT WIN32)
    target_compile_options(proctest PUBLIC -fshort-wchar)
endif()

if(NOT MSVC)
	target_compile_options(proctest PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)
endif()
