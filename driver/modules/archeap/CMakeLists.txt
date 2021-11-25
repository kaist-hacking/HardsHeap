add_executable(archeap_child child.c)
target_link_libraries(archeap_child child)
set_target_properties(archeap_child PROPERTIES OUTPUT_NAME child)

add_executable(archeap_parent parent.cpp)
target_link_libraries(archeap_parent parent)
set_target_properties(archeap_parent PROPERTIES OUTPUT_NAME parent)
