add_library(ctfir_core STATIC
  util.cpp
  sha256.cpp
  model.cpp
  session.cpp
  evidence.cpp
  report.cpp
  advice.cpp
)
# 平台层编入同一静态库（仅本平台源码）
if(WIN32)
  target_sources(ctfir_core PRIVATE
    ../platform/win/host_info.cpp
    ../platform/win/modules.cpp
    ../platform/win/mod_w.cpp
    ../platform/win/mod_w2.cpp
  )
else()
  target_sources(ctfir_core PRIVATE
    ../platform/linux/host_info.cpp
    ../platform/linux/modules.cpp
    ../platform/linux/mod_a.cpp
    ../platform/linux/mod_b.cpp
  )
endif()
if(MSVC)
  target_compile_options(ctfir_core PRIVATE /W3)
endif()
