# vmshell
**vmshell** is a tool that provides a shell into KVM-based guests. It does not require patching the kernel, virtual machine manager, nor does it require any special features of the VMM being activated(such as gdbstub). Currently, only x86-64 is supported. While portability is a goal, it currently does not work on Firecracker(see [BUGS](#BUGS)). It should work on most versions of Qemu.

## License

**vmhsell** is licensed under the GPLv3 license. See [LICENSE](LICENSE) for details.

## Installation
Static binaries are provided in the [Releases](https://github.com/CajuM/vmshell/releases) page.

## Usage
```
vmshell <pid> <stage2.bin>
```
Where pid is the target process(ex Qemu) and stage2.bin is the path to a stage2 payload. Sample stage2 payloads are provided in the stage2 directory. The only working payload is *stage2-linux.bin* the rest are for testing purposes.

For safety reasons, **DO NOT** run on a production VM, it may crash.

For example, one could run **vmshell** like so:
```
vmshell $(pgrep qemu) stage2/stage2-linux.bin
```

## Building from source
The only dependencies are a C compiler, a C library plus headers and GNU Make
```
$ sudo apt-get -y install gcc make
$ make
```

## BUGS
* Proper documentation is currently missing.
* VMMs making use of seccomp may not work, depending on the filters in use.
* /dev/kvm must be opened in the target process, although this may not be necessary.
* Firecracker is currently not supported due to the above two bugs, even with seccomp disabled.
* The only supported guest OS, for now, is Linux.
* The current version will only infect TID 1 in the guest OS.
* It requires a fairly active `init` process, otherwise it will not spawn a shell in the guest OS.
* If ran too early during the guest's boot process the shell might end-up in an empty initramfs.
