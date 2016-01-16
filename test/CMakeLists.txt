# CMake MODULES
INCLUDE (FindPkgConfig)

# REQUIRED LIBRARIES
pkg_check_modules(LIBCHECK REQUIRED check)
include_directories(${LIBCHECK_INCLUDE_DIRS})

# TEST EXECUTABLES
add_executable(check_sanity check_sanity.c)
add_executable(check_sodium_sanity check_sodium_sanity.c)
add_executable(c_round_trip round_trip.c
	$<TARGET_OBJECTS:chunk.o>
	$<TARGET_OBJECTS:key.o>
	$<TARGET_OBJECTS:util.o>
	$<TARGET_OBJECTS:encryption.o>
	$<TARGET_OBJECTS:decryption.o>)

# TESTS
add_test(NAME sanity COMMAND check_sanity)
add_test(NAME sodium_sanity COMMAND check_sodium_sanity)
add_test(NAME check_box_size COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/check_box_size.sh")
add_test(NAME c_round_trip COMMAND c_round_trip ${CMAKE_CURRENT_SOURCE_DIR}/lorem.txt)
add_test(NAME round_trip COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/round_trip.sh ${CMAKE_CURRENT_SOURCE_DIR}/lorem.txt)
add_test(NAME round_trip_big COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/round_trip_big.sh ${CMAKE_CURRENT_SOURCE_DIR}/lorem.txt)
add_test(NAME round_trip_empty COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/round_trip_empty.sh)
add_test(NAME check_integrity COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/check_integrity.sh ${CMAKE_CURRENT_SOURCE_DIR}/lorem.txt)

# LINKING
target_link_libraries(check_sanity PRIVATE ${LIBCHECK_LDFLAGS})
target_link_libraries(check_sodium_sanity PRIVATE ${LIBCHECK_LDFLAGS} ${LIBSODIUM_LDFLAGS})
target_link_libraries(c_round_trip PRIVATE ${LIBCHECK_LDFLAGS} ${LIBSODIUM_LDFLAGS})
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  target_link_libraries(c_round_trip PRIVATE argp)
endif()
