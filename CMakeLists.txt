cmake_minimum_required(VERSION 3.0)

# include_directories($PROJECT_SOURCE_DIR/)

project(inderpreet_demo C)
find_library(LIB paho-mqtt3c mbedlts ${PROJECT_SOURCE_DIR}/lib)

# add_subdirectory(mbedlts)

add_executable(inderpreet_demo main.c)

target_link_libraries(inderpreet_demo mbedtls mbedx509 mbedcrypto ${LIB})
