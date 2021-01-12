# Test binaries for the acceptance test suite

For the acceptance test suite of the *cwe_checker*,
the C-files inside this directory have to be compiled for a variety of CPU architectures and C-compilers.
The provided dockerfile should be used for the build process.

## Prerequisites

- Have Docker installed on your system

## Build commands

Inside this directory run the following commands:
```shell
docker build -t cross_compiling .
docker run --rm -v $(pwd)/build:/home/cwe/artificial_samples/build cross_compiling sudo /home/cwe/.local/bin/scons
```

