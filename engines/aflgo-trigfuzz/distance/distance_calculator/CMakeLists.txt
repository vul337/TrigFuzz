cmake_minimum_required(VERSION 3.4.3)
project(distance_calculator)

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE "Release" CACHE
        STRING "Choose the type of build." FORCE)
endif()
set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -march=native")


find_package(Boost
    REQUIRED
    COMPONENTS program_options graph regex
    )

set(CMAKE_CXX_STANDARD 14)

add_executable(distance.bin distance.bin.cc)
target_link_libraries(distance.bin ${Boost_LIBRARIES})
