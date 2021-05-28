with import <nixpkgs> { };

mkShell {
  name = "vmshell-env";

  buildInputs = [
    gnumake
    stdenv
    zsh
  ];
}
