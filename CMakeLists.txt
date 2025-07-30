cmake_minimum_required(VERSION 2.6)
project(cache-poisoning-tool)

find_package( PkgConfig )
pkg_check_modules(YAML_CPP REQUIRED yaml-cpp)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(Boost_ADDITIONAL_VERSIONS "1.53" )
find_package( Threads )
find_package( Boost 1.53 )
find_package( OpenSSL REQUIRED )
# find_package( yaml-cpp )
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${YAML_CPP_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})
link_directories(${YAML_CPP_LIBRARY_DIRS})

add_definitions("-Wall -std=c++11 -g -fPIC -DBOOST_ALL_DYN_LINK")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_EXE_LINKER_FLAGS "-L/usr/local/lib -L/usr/local/lib64 ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_EXE_LINKER_FLAGS}")

message( "crypto lib: ${OPENSSL_CRYPTO_LIBRARY}" )
message( "ssl lib: ${OPENSSL_SSL_LIBRARY}" )
message( "lib: ${_OPENSSL_LIBDIR}" )
add_subdirectory( src )

#if(NOT without-test)
#  include_directories ("${PROJECT_SOURCE_DIR}/src")
#  enable_testing()
#  add_subdirectory(tests)
#endif()


