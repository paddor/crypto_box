cmake_minimum_required(VERSION 2.8.12)

# project name and language
project("Crypto Box" C)

# C standard
add_definitions(-std=gnu99)

# variables for packaging
set(CPACK_PACKAGE_NAME "crypto_box")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "7")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
	"Easy to use, strong symmetric encryption on the command line.")

# CMake module for packaging
SET(CPACK_SOURCE_GENERATOR "TBZ2;TGZ;TXZ")
SET(CPACK_SOURCE_IGNORE_FILES
"/\\\\.git/;/\\\\.gitignore$;/\\\\.travis.yml$;/session\\\\.vim$;/ci-scripts/;/\\\\.DS_Store$")
INCLUDE (CPack)

# CMake modules for checking dependencies
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckTypeSize)
INCLUDE (CheckFunctionExists)
INCLUDE (FindPkgConfig)

# REQUIRED LIBRARIES
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

# OPTIONAL LIBRARIES
pkg_check_modules(LIBCHECK check)

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
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux" AND NOT HAVE_ARGP_H)
	message(FATAL_ERROR "Couldn't find argp.h")
endif()

# TYPES
CHECK_TYPE_SIZE(uint8_t UINT8_T LANGUAGE C)
if(NOT HAVE_UINT8_T)
	message(FATAL_ERROR "Type uint8_t isn't supported on this system")
endif()

# FUNCTIONS
CHECK_FUNCTION_EXISTS(atexit HAVE_ATEXIT)
CHECK_FUNCTION_EXISTS(malloc HAVE_MALLOC)

# config.h
configure_file(src/config.h.in src/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/src)

# other header files
include_directories(${CMAKE_SOURCE_DIR}/src)

# OBJECT files (so they're compiled only once)
add_library(arguments.o OBJECT src/arguments.c)
add_library(chunk.o OBJECT src/chunk.c)
add_library(key.o OBJECT src/key.c)
add_library(encryption.o OBJECT src/encryption.c)
add_library(decryption.o OBJECT src/decryption.c)
add_library(util.o OBJECT src/util.c)

# EXECUTABLES
add_executable(lock_box src/lock_box.c
	$<TARGET_OBJECTS:arguments.o>
	$<TARGET_OBJECTS:chunk.o>
	$<TARGET_OBJECTS:key.o>
	$<TARGET_OBJECTS:util.o>
	$<TARGET_OBJECTS:encryption.o>)
add_executable(open_box src/open_box.c
	$<TARGET_OBJECTS:arguments.o>
	$<TARGET_OBJECTS:chunk.o>
	$<TARGET_OBJECTS:key.o>
	$<TARGET_OBJECTS:util.o>
	$<TARGET_OBJECTS:decryption.o>)

# LINKING
target_link_libraries(lock_box PRIVATE ${LIBSODIUM_LDFLAGS})
target_link_libraries(open_box PRIVATE ${LIBSODIUM_LDFLAGS})

# non-Linux systems like OSX and OpenBSD
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  find_library(HAVE_LIBARGP argp)
  if(NOT HAVE_LIBARGP)
    message(FATAL_ERROR "Couldn't find argp! Try installing 'argp-standalone'.")
  endif()

  # linking
  target_link_libraries(lock_box PRIVATE argp)
  target_link_libraries(open_box PRIVATE argp)
endif()

# TESTING
if (${LIBCHECK_FOUND})
  enable_testing()
  add_subdirectory("test")
endif()

# INSTALLATION
INCLUDE(GNUInstallDirs)
INSTALL(TARGETS lock_box open_box RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
