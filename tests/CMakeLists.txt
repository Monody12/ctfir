add_executable(ctfir_tests
  test_main.cpp
  test_engine.cpp
  test_platform.cpp
)
target_link_libraries(ctfir_tests PRIVATE ctfir_core)
if(WIN32)
  target_link_libraries(ctfir_tests PRIVATE user32 shell32)
endif()
