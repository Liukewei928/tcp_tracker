file(REMOVE_RECURSE
  "tcp_state_tracker"
  "tcp_state_tracker.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/tcp_state_tracker.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
