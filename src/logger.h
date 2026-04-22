#pragma once
#include <cstdio>
#include <cstdarg>

// 全局日志文件句柄
extern FILE* g_logFile;

// 日志初始化：创建logs目录，生成带时间戳的日志文件
void LogInit();

// INFO日志：仅写文件（不干扰控制台交互）
void LogInfo(const char* format, ...);

// ERROR日志：文件 + 控制台（用户可见）
void LogError(const char* format, ...);

// 日志关闭：释放文件句柄
void LogClose();