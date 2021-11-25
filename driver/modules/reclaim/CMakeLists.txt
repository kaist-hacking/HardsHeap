add_executable(reclaim_child child.c)
target_link_libraries(reclaim_child child)
set_target_properties(reclaim_child PROPERTIES OUTPUT_NAME child)

add_executable(reclaim_parent parent.cpp)
target_link_libraries(reclaim_parent parent)
set_target_properties(reclaim_parent PROPERTIES OUTPUT_NAME parent)
