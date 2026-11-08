add_executable(ctfir_tests
  test_main.cpp
  test_engine.cpp
)
target_link_libraries(ctfir_tests PRIVATE ctfir_core)
