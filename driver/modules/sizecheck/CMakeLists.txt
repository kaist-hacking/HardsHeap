add_executable(sizecheck_child child.c)
target_link_libraries(sizecheck_child child)
set_target_properties(sizecheck_child PROPERTIES OUTPUT_NAME child)

add_executable(sizecheck_parent parent.cpp)
target_link_libraries(sizecheck_parent parent)
set_target_properties(sizecheck_parent PROPERTIES OUTPUT_NAME parent)
