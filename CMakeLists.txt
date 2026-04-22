cmake_minimum_required(VERSION 3.20)
project(rust_wrapper)
set(CMAKE_CXX_STANDARD 17)

# 启用Windows资源编译（MinGW兼容）
enable_language(RC)

# 编译目标：包含cpp+rc资源文件
add_executable(wrapper main.cpp resource.rc)

# 控制台程序
set_target_properties(wrapper PROPERTIES WIN32_EXECUTABLE OFF)