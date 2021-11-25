file(GLOB SOURCES *.c *.cpp)

add_library(parent STATIC ${SOURCES} )
target_link_libraries(parent common ${Boost_LIBRARIES} ${CMAKE_DL_LIBS})
target_include_directories(parent
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  )

