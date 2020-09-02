cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(muw)

set(SRC_FILES
	libmuw.c)

add_compile_options(-fshort-wchar -masm=intel -nostdlib)
add_compile_options(-Wall -Werror=cast-function-type -Wno-expansion-to-defined
	-Wunused-parameter -Wtype-limits -Wextra -Wconversion
	-Werror=implicit-function-declaration)

add_library(muw SHARED ${SRC_FILES})
add_library(muwstatic STATIC ${SRC_FILES})

target_link_options(muwstatic PUBLIC -nostdlib)

set_target_properties(muw PROPERTIES PUBLIC_HEADER muw.h)

install(TARGETS muw muwstatic
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        PRIVATE_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
