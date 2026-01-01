cmake_minimum_required(VERSION 3.16)
project(PacketGhost VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wpedantic)

# ==========================================
# 1. 引入 GTest：优先系统包，找不到再回退到 FetchContent
# ==========================================
find_package(GTest QUIET)
if (NOT GTest_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
  )
  # For Windows: Prevent overriding the parent project's compiler/linker settings
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
endif()

# ==========================================
# 2. 查找 Netfilter 依赖
# ==========================================
find_library(NFQ_LIB netfilter_queue REQUIRED)
find_library(NFNL_LIB nfnetlink REQUIRED)

# ==========================================
# 3. 核心库 (GhostCore)
# 把所有的核心逻辑放在这里，方便测试调用
# ==========================================
# 排除 main.cpp，因为库里不能有 main 函数
file(GLOB_RECURSE CORE_SOURCES "src/*.cpp")
list(FILTER CORE_SOURCES EXCLUDE REGEX "src/main.cpp")

add_library(ghost_core STATIC ${CORE_SOURCES})
target_include_directories(ghost_core PUBLIC src)
target_link_libraries(ghost_core PUBLIC ${NFQ_LIB} ${NFNL_LIB} pthread)

# ==========================================
# 4. 主程序 (PacketGhost)
# ==========================================
add_executable(packet_ghost src/main.cpp)
target_link_libraries(packet_ghost PRIVATE ghost_core)

# ==========================================
# 5. 单元测试 (UnitTests)
# ==========================================
enable_testing()

# 查找 tests 目录下的所有测试文件
file(GLOB TEST_SOURCES "tests/*.cpp")

add_executable(unit_tests ${TEST_SOURCES})
# 链接 GTest 和我们的核心库
target_link_libraries(unit_tests PRIVATE GTest::gtest_main ghost_core)

# 注册测试，方便用 ctest 命令运行
include(GoogleTest)
gtest_discover_tests(unit_tests)
