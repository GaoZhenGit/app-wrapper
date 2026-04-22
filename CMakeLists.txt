cmake_minimum_required(VERSION 3.20)
project(pe_wrapper)
set(CMAKE_CXX_STANDARD 17)

# 启用Windows资源编译
enable_language(RC)

# 添加源文件
set(SOURCES
    src/logger.cpp
    src/pe_parser.cpp
    src/pe_loader.cpp
    src/executor.cpp
    src/main.cpp
    resource.rc
)

# 编译目标
add_executable(wrapper ${SOURCES})

# 包含头文件目录
target_include_directories(wrapper PRIVATE src)

# 控制台程序
set_target_properties(wrapper PROPERTIES WIN32_EXECUTABLE OFF)