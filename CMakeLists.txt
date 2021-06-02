cmake_minimum_required(VERSION 2.8.12)

project(sscep)

if (WIN32)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

set(OPENSSL_MIN_VERSION 1.1.0)
find_package(OpenSSL REQUIRED)

option(ENABLE_ENGINES "Enable support for OpenSSL ENGINE API")

# For IDE such as Visual Studio we include also the header files
set(SSCEP_SOURCES
    src/sscep.c
    src/sscep.h
    src/conf.h
    src/cmd.h
    src/getopt.c
    src/getopt.h
    src/configuration.c
    src/configuration.h
    src/net.c
    src/picohttpparser.c
    src/picohttpparser.h
    src/ias.c
    src/ias.h
    src/pkcs7.c
    src/fileutils.c
    src/fileutils_capi.h
    src/sceputils.c
)

if (ENABLE_ENGINES)
    set(SSCEP_SOURCES
        ${SSCEP_SOURCES}
        src/engine.c
        src/engine.h
    )
    add_definitions(-DWITH_ENGINES)
endif()

if (MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

add_executable(${PROJECT_NAME} ${SSCEP_SOURCES})

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME}
    ${OPENSSL_LIBRARIES}
)

if (WIN32)
    target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
endif()

install(
    TARGETS ${PROJECT_NAME}
    DESTINATION bin
)

include(CPack)
