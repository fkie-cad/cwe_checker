# Test binaries for the acceptance test suite

For the acceptance test suite of the *cwe_checker*,
the C-files inside this directory have to be compiled for a variety of CPU architectures and C-compilers.
The provided dockerfile should be used for the build process.

## Prerequisites

- Have Docker or Podman installed on your system

## Build commands

Inside this directory run the following commands:
```shell
docker build -t cross_compiling .
docker run --rm -v $(pwd)/build:/home/cwe/artificial_samples/build cross_compiling sudo python3 -m SCons
```
If instead of Docker you use Podman, it's necessary to add also the `--security-opt label=disable` for mounting the volume:
```shell
podman build -t cross_compiling .
podman run --rm -v $(pwd)/build:/home/cwe/artificial_samples/build --security-opt label=disable cross_compiling sudo python3 -m SCons
```
