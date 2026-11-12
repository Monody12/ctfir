add_executable(ctfir_tests
  test_main.cpp
  test_engine.cpp
  test_platform.cpp
  test_log_attack.cpp
  test_evt_xml.cpp
  test_triage.cpp
  test_compat.cpp
)
target_link_libraries(ctfir_tests PRIVATE ctfir_core)
if(WIN32)
  target_link_libraries(ctfir_tests PRIVATE user32 shell32)
endif()
