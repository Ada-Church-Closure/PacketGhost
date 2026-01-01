cmake_minimum_required(VERSION 3.10)
project(PacketGhost LANGUAGES C)

# 使用 C11 标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 开启调试信息(-g)和所有警告
add_compile_options(-Wall -Wextra -g)

# 查找 Netfilter 库
find_library(NFQ_LIB netfilter_queue REQUIRED)
find_library(NFNL_LIB nfnetlink REQUIRED)

# 包含头文件路径
include_directories(src)

# 自动收集所有源文件
file(GLOB_RECURSE SOURCES "src/*.c")

# 生成可执行文件
add_executable(packet_ghost ${SOURCES})
target_link_libraries(packet_ghost ${NFQ_LIB} ${NFNL_LIB})

file(GLOB_RECURSE CORE_SOURCES "src/*.c")
list(FILTER CORE_SOURCES EXCLUDE REGEX "src/main.c")

# 2. 收集所有测试代码
file(GLOB_RECURSE TEST_SOURCES "tests/*.c")

# 3. 生成测试可执行文件
add_executable(run_tests ${TEST_SOURCES} ${CORE_SOURCES})

# 4. 链接库
target_link_libraries(run_tests ${NFQ_LIB} ${NFNL_LIB})

# 5. 添加 make test 命令
add_custom_target(test 
    COMMAND ./run_tests 
    DEPENDS run_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running Unit Tests..."
)
