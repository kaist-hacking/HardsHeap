add_executable(spray_child child.c)
target_link_libraries(spray_child child)
set_target_properties(spray_child PROPERTIES OUTPUT_NAME child)

add_executable(spray_parent parent.cpp)
target_link_libraries(spray_parent parent)
set_target_properties(spray_parent PROPERTIES OUTPUT_NAME parent)
