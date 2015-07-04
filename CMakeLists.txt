cmake_minimum_required(VERSION 2.8.12)

# config.h
file(STRINGS VERSION package_version)
configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# EXECUTABLES
add_executable(lock_box src/lock_box.c src/crypto_box.c)
add_executable(open_box src/open_box.c src/crypto_box.c)

add_executable(check_sodium_sanity test/check_sodium_sanity.c)

# LIBRARIES
target_link_libraries(lock_box PRIVATE sodium argp)
target_link_libraries(open_box PRIVATE sodium argp)

target_link_libraries(check_sodium_sanity PRIVATE check sodium m pthread rt)

# TESTING
enable_testing()
add_test(NAME sodium_sanity COMMAND check_sodium_sanity)
