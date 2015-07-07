cmake_minimum_required(VERSION 2.8.12)

# project name and language
project("Crypto Box" C)

# variables for packaging
set(CPACK_PACKAGE_NAME "crypto_box")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "5")
set(CPACK_PACKAGE_VERSION_PATCH "0")

# CMake module for packaging
INCLUDE (CPack)

# CMake modules for checking dependencies
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckFunctionExists)
INCLUDE (FindPkgConfig)

# REQUIRED LIBRARIES
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# HEADERS
CHECK_INCLUDE_FILES("stdio.h" HAVE_STDIO_H)
CHECK_INCLUDE_FILES("fcntl.h" HAVE_FCNTL_H)
CHECK_INCLUDE_FILES("stdint.h" HAVE_STDINT_H)
CHECK_INCLUDE_FILES("stdlib.h" HAVE_STDLIB_H)
CHECK_INCLUDE_FILES("string.h" HAVE_STRING_H)
CHECK_INCLUDE_FILES("unistd.h" HAVE_UNISTD_H)
CHECK_INCLUDE_FILES("sys/stat.h" HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES("stdbool.h" HAVE__BOOL)
CHECK_INCLUDE_FILES("memory.h" HAVE_MEMORY_H)
CHECK_INCLUDE_FILES("argp.h" HAVE_ARGP_H)


# fail if a header file couldn't be found
if(NOT HAVE_STDIO_H)
	message(FATAL_ERROR "Couldn't find stdio.h")
endif()
if(NOT HAVE_FCNTL_H)
	message(FATAL_ERROR "Couldn't find fcntl.h")
endif()
if(NOT HAVE_STDINT_H)
	message(FATAL_ERROR "Couldn't find stdint.h")
endif()
if(NOT HAVE_STDLIB_H)
	message(FATAL_ERROR "Couldn't find stdlib.h")
endif()
if(NOT HAVE_STRING_H)
	message(FATAL_ERROR "Couldn't find string.h")
endif()
if(NOT HAVE_UNISTD_H)
	message(FATAL_ERROR "Couldn't find unistd.h")
endif()
if(NOT HAVE_SYS_STAT_H)
	message(FATAL_ERROR "Couldn't find sys/stat.h")
endif()
if(NOT HAVE__BOOL)
	message(FATAL_ERROR "Couldn't find stdbool.h")
endif()
if(NOT HAVE_MEMORY_H)
	message(FATAL_ERROR "Couldn't find memory.h")
endif()
if(NOT HAVE_ARGP_H)
	message(FATAL_ERROR "Couldn't find argp.h")
endif()

# TYPES
# TODO: uint8_t, ...

# FUNCTIONS
CHECK_FUNCTION_EXISTS(atexit HAVE_ATEXIT)
CHECK_FUNCTION_EXISTS(malloc HAVE_MALLOC)

# config.h
configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# EXECUTABLES
add_executable(lock_box src/lock_box.c src/crypto_box.c)
add_executable(open_box src/open_box.c src/crypto_box.c)

# LINKING
target_link_libraries(lock_box PRIVATE ${LIBSODIUM_LDFLAGS})
target_link_libraries(open_box PRIVATE ${LIBSODIUM_LDFLAGS})

# OSX
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  find_library(HAVE_LIBARGP argp)
  if(NOT HAVE_LIBARGP)
    message(FATAL_ERROR "Couldn't find argp! Install with: brew install argp-standalone")
  endif()

  # linking
  target_link_libraries(lock_box PRIVATE argp)
  target_link_libraries(open_box PRIVATE argp)
endif()

# TESTING
enable_testing()
add_subdirectory("test")
