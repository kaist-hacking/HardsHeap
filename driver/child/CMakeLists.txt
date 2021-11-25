file(GLOB SOURCES "*.c")

add_library(child STATIC ${SOURCES})
target_link_libraries(child common)
target_include_directories(child
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  )

