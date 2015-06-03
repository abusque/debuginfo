#debuginfo

Extract debug info from an executable using libelf and
libdwarf. Eventually to be used to map trace events to the
corresponding source code, via instruction pointer addresses.

## Requirements

You will need both libelf and libdwarf installed on your system. On
Arch Linux, these can be installed from the packages `elfutils` and
`libdwarf`, respectively.

To compile, simply run `make` in the root directory of the project.

## Usage

You can launch the program by executing `./debuginfo
<path/to/executable>`.
