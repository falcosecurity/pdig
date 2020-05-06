cmake_minimum_required (VERSION 2.6)

project(pdig)

if(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Release)
endif()

ADD_DEFINITIONS(-DUDIG)
set(CMAKE_C_FLAGS_DEBUG "-Og -g -D_DEBUG -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "-Og -g -D_DEBUG -Wall")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wall")

if(NOT SYSDIG_DIR)
	SET(SYSDIG_DIR ../sysdig)
endif()

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${SYSDIG_DIR}/driver)
include_directories(${SYSDIG_DIR}/userspace/libscap)

add_executable(pdig
    pdig.cc
	pdig_compat.c
    udig_procs.c
    ${SYSDIG_DIR}/driver/dynamic_params_table.c
    ${SYSDIG_DIR}/driver/event_table.c
    ${SYSDIG_DIR}/driver/flags_table.c
    ${SYSDIG_DIR}/driver/ppm_events.c
    ${SYSDIG_DIR}/driver/ppm_fillers.c
    ${SYSDIG_DIR}/driver/fillers_table.c
    ${SYSDIG_DIR}/driver/syscall_table.c
    ${SYSDIG_DIR}/userspace/libscap/scap_udig.c
)

target_link_libraries(pdig rt)

set_property(TARGET pdig PROPERTY CXX_STANDARD 11)
