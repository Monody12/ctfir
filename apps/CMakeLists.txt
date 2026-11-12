# CLI（全平台）
add_executable(ctfir cli/main.cpp)
target_link_libraries(ctfir PRIVATE ctfir_core)

# Windows GUI（仅 Windows；WP5 完整化）
if(WIN32)
  add_executable(ctfir-gui WIN32 win-gui/main.cpp)
  target_link_libraries(ctfir-gui PRIVATE ctfir_core user32 gdi32 shell32 comctl32)
endif()
