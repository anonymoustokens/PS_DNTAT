cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(DNTAT VERSION 1.0)

# if(NOT CMAKE_BUILD_TYPE)
#     set(CMAKE_BUILD_TYPE Release)
# endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Define the path to the MCL library
#set(MCLPATH "/Users/simonlion/mcl")

include_directories(${CMAKE_SOURCE_DIR}/inc /Users/simonlion/mcl/include)

file(GLOB SRC_FILES ${CMAKE_SOURCE_DIR}/src/*.cpp)

# Create the executables
add_executable(DNTAT ${SRC_FILES})


# Link with the MCL library (adjust with the actual library name) # Replace 'mcl' with the actual library name if needed
target_link_libraries(DNTAT /Users/simonlion/mcl/lib/libmcl.a /Users/simonlion/mcl/lib/libmclbn256.a)

set(CMAKE_BUILD_TYPE Release)
target_compile_options(DNTAT PRIVATE -O3 -march=native)

