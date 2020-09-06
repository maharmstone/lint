cmake_minimum_required(VERSION 3.10)

project(tests)

add_executable(regtest regtest.c)

if(WIN32)
    target_link_libraries(regtest ntdll)
else()
    target_link_libraries(regtest muwstatic)
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
    target_link_libraries(filetest muwstatic)
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
    target_link_libraries(threadtest muwstatic)
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
    target_link_libraries(proctest muwstatic)
endif()

if(NOT WIN32)
    target_compile_options(proctest PUBLIC -fshort-wchar)
endif()

if(NOT MSVC)
	target_compile_options(proctest PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)
endif()

# --------------------

add_executable(timertest timertest.c)

if(WIN32)
    target_link_libraries(timertest ntdll)
else()
    target_link_libraries(timertest muwstatic)
endif()

if(NOT WIN32)
    target_compile_options(timertest PUBLIC -fshort-wchar)
endif()

if(NOT MSVC)
	target_compile_options(timertest PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)
endif()

# --------------------

add_executable(mutanttest mutanttest.c)

if(WIN32)
    target_link_libraries(mutanttest ntdll)
else()
    target_link_libraries(mutanttest muwstatic)
endif()

if(NOT WIN32)
    target_compile_options(mutanttest PUBLIC -fshort-wchar)
endif()

if(NOT MSVC)
	target_compile_options(mutanttest PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)
endif()
