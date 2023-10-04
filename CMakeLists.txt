cmake_minimum_required(VERSION 3.5)

project(ibdev2netdev C)

set(CMAKE_C_FLAGS "-O2 -Wall -Wextra -Werror -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings -Wformat=2 -Wformat-nonliteral -Wdate-time -Wnested-externs -Wshadow -Wstrict-prototypes -Wold-style-definition -Wredundant-decls")
FILE(GLOB Ibdev2netdevSources *.c)
add_executable(ibdev2netdev ${Ibdev2netdevSources})
target_link_libraries(ibdev2netdev LINK_PRIVATE ibverbs)
install (TARGETS ibdev2netdev DESTINATION sbin)
