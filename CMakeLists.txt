cmake_minimum_required(VERSION 3.16)

# 项目名称
project(PacketGhost VERSION 0.1.0 LANGUAGES CXX)

# 设置 C++ 标准 (C++17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 开启编译警告
add_compile_options(-Wall -Wextra -Wpedantic)

# 查找依赖库
find_library(NFQ_LIB netfilter_queue REQUIRED)
find_library(NFNL_LIB nfnetlink REQUIRED)

# 包含头文件目录
include_directories(src)

# 自动查找 src 下所有源文件
file(GLOB_RECURSE SOURCES "src/*.cpp")
message(STATUS "Found Source Files: ${SOURCES}")

# 生成可执行文件
add_executable(packet_ghost ${SOURCES})

# 链接库
target_link_libraries(packet_ghost PRIVATE ${NFQ_LIB} ${NFNL_LIB})