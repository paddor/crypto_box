cmake_minimum_required(VERSION 2.8.12)

# project name and language
project("Crypto Box" C)

# config.h
file(STRINGS VERSION package_version)
configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# EXECUTABLES
add_executable(lock_box src/lock_box.c src/crypto_box.c)
add_executable(open_box src/open_box.c src/crypto_box.c)

add_executable(check_sanity test/check_sanity.c)
add_executable(check_sodium_sanity test/check_sodium_sanity.c)

# LIBRARIES
target_link_libraries(lock_box PRIVATE sodium)
target_link_libraries(open_box PRIVATE sodium)
target_link_libraries(check_sanity PRIVATE check)
target_link_libraries(check_sodium_sanity PRIVATE check sodium)


# CMake MODULES
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckFunctionExists)
INCLUDE (FindPkgConfig)


# PLATFORM CHECK

# libraries
pkg_check_modules(LIBCHECK REQUIRED check)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# OSX
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
#pkg_check_modules(LIBARGP REQUIRED libargp)
  find_library(HAVE_LIBARGP argp)
  if(NOT HAVE_LIBARGP)
    message(FATAL_ERROR "Couldn't find argp! Install with: brew install argp-standalone")
  endif()

  target_link_libraries(lock_box PRIVATE argp)
  target_link_libraries(open_box PRIVATE argp)
endif()

# headers
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

# types

# functions
CHECK_FUNCTION_EXISTS(atexit HAVE_ATEXIT)
CHECK_FUNCTION_EXISTS(malloc HAVE_MALLOC)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  target_link_libraries(check_sanity PRIVATE m pthread rt)
  target_link_libraries(check_sodium_sanity PRIVATE m pthread rt)
endif()



# TESTING
enable_testing()
add_test(NAME sanity COMMAND check_sanity)
add_test(NAME sodium_sanity COMMAND check_sodium_sanity)
