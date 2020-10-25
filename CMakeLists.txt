cmake_minimum_required(VERSION 2.8.12)

project(sscep)

find_package(OpenSSL REQUIRED)

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
    src/init.c
    src/engine.c
    src/engine.h
    src/net.c
    src/ias.c
    src/ias.h
    src/pkcs7.c
    src/fileutils.c
    src/fileutils_capi.h
    src/sceputils.c
)

if (WIN32)
    list(APPEND SSCEP_SOURCES
        src/engines/sscep_capi.c
        src/engines/sscep_capi.h)
endif()

add_executable(${PROJECT_NAME} ${SSCEP_SOURCES})

include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(${PROJECT_NAME}
    ${OPENSSL_LIBRARIES}
)

install(
    TARGETS ${PROJECT_NAME}
    DESTINATION bin
)

include(CPack)
