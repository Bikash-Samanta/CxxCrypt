enable_testing()

file(GLOB TESTS "*.cpp")

foreach(test ${TESTS})
    get_filename_component(test_name ${test} NAME_WE)

    add_executable(${test_name} ${test})

    target_link_libraries(${test_name} PRIVATE CxxCrypt)
endforeach()