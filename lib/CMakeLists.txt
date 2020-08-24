cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(muw)

set(SRC_FILES
	libmuw.c)

add_library(muw STATIC ${SRC_FILES})

target_compile_options(muw PUBLIC -fshort-wchar -masm=intel -nostdlib)
target_link_options(muw PUBLIC -nostdlib)

target_compile_options(muw PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -Werror=implicit-function-declaration)

set_target_properties(muw PROPERTIES PUBLIC_HEADER muw.h)

install(TARGETS muw
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        PRIVATE_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
