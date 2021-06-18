with import <nixpkgs> { };

mkShell {
  name = "vmshell-env";

  buildInputs = [
    firecracker
    gdb
    gnumake
    qemu
    stdenv
    zsh
  ];
}
