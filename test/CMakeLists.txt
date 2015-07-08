# CMake MODULES
INCLUDE (FindPkgConfig)

# REQUIRED LIBRARIES
pkg_check_modules(LIBCHECK REQUIRED check)

# TEST EXECUTABLES
add_executable(check_sanity check_sanity.c)
add_executable(check_sodium_sanity check_sodium_sanity.c)

# TESTS
add_test(NAME sanity COMMAND check_sanity)
add_test(NAME sodium_sanity COMMAND check_sodium_sanity)
add_test(NAME round_trip COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/round_trip.sh ${CMAKE_CURRENT_SOURCE_DIR}/lorem.txt)
add_test(NAME check_box_size COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/check_box_size.sh")

# LINKING
target_link_libraries(check_sanity PRIVATE ${LIBCHECK_LDFLAGS})
target_link_libraries(check_sodium_sanity PRIVATE ${LIBCHECK_LDFLAGS} ${LIBSODIUM_LDFLAGS})
