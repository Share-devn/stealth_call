cmake_minimum_required(VERSION 3.15)
project(stealth_call LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME} main.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

string(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

target_compile_options(${PROJECT_NAME} PRIVATE /GS- /GR- /Zl /O2 /Oi /D_HAS_EXCEPTIONS=0)

target_link_options(${PROJECT_NAME} PRIVATE
    /NODEFAULTLIB
    /ENTRY:entry_point
    /SUBSYSTEM:CONSOLE
    /MERGE:.rdata=.text
)

target_link_libraries(${PROJECT_NAME} PRIVATE kernel32.lib)
