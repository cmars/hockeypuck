with import <nixos-unstable> {};
runCommand "dummy" { buildInputs = [ go_1_18 gnumake gcc ]; } ""
