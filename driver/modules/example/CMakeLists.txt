add_executable(example_child child.c)
target_link_libraries(example_child child)
set_target_properties(example_child PROPERTIES OUTPUT_NAME child)

add_executable(example_parent parent.cpp)
target_link_libraries(example_parent parent)
set_target_properties(example_parent PROPERTIES OUTPUT_NAME parent)
