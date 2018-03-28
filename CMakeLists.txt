
cmake_minimum_required(VERSION 2.8.11)
project(SSCEP)

add_executable (${PROJECT_NAME} sscep.c init.c net.c sceputils.c pkcs7.c ias.c fileutils.c configuration.c engine.c)

target_link_libraries (${PROJECT_NAME} ssl crypto)

install(TARGETS ${PROJECT_NAME} DESTINATION bin)


SET(CPACK_PACKAGE_CONTACT "Scott T. Hardin")

INCLUDE(CPack)
