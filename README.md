<p align="center">
    <img src="doc/images/cwe_checker_logo.png" alt="cwe_checker logo" width="50%" height="50%"/>
</p>

# cwe_checker #
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/9dbf158110de427d893b40ba397b94bc)](https://www.codacy.com/app/weidenba/cwe_checker?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=fkie-cad/cwe_checker&amp;utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.com/fkie-cad/cwe_checker.svg?branch=master)](https://travis-ci.com/fkie-cad/cwe_checker)
![Docker-Pulls](https://img.shields.io/docker/pulls/fkiecad/cwe_checker.svg)
[![Documentation](https://img.shields.io/badge/doc-stable-green.svg)](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html)

**NOTE:** We recently changed our default analysis backend from BAP to the newer Ghidra backend.
The switch causes some changes in both the command line interface and the docker image interface.
Be sure to update your scripts accordingly!
Alternatively, the stable version still uses the old interface.

## What is cwe_checker? ##
*cwe_checker* is a suite of checks to detect common bug classes such as use of dangerous functions and simple integer overflows.
These bug classes are formally known as [Common Weakness Enumerations](https://cwe.mitre.org/) (CWEs).
Its main goal is to aid analysts to quickly find vulnerable code paths.

Its main focus are ELF binaries that are commonly found on Linux and Unix operating systems.
The *cwe_checker* uses [Ghidra](https://ghidra-sre.org/) to disassemble binaries into one common intermediate representation
and implements its own analyses on this IR.
Hence, the analyses can be run on all CPU architectures that Ghidra can disassemble,
which makes the *cwe_checker* a valuable tool for firmware analysis.

The following arguments should convince you to give *cwe_checker* a try:
-  it is very easy to set up, just build the Docker container!
-  it analyzes ELF binaries of several CPU architectures including x86, ARM, MIPS, and PPC
-  it is extensible due to its plugin-based architecture
-  it is configureable, e.g. apply analyses to new APIs
-  view results annotated in Ghidra
-  *cwe_checker* can be integrated as a plugin into [FACT](https://github.com/fkie-cad/FACT_core)

<p align="center">
    <img src="doc/images/example_usage.png" alt="Usage Example" width="80%" height="80%"/>
</p>

## Installation ##

### Using the docker image ###

The simplest way is to pull the latest Docker image from [dockerhub](https://hub.docker.com/r/fkiecad/cwe_checker):
-   `docker pull fkiecad/cwe_checker:latest` yields an image based on the current master branch.
-   `docker pull fkiecad/cwe_checker:stable` yields an image based on the latest stable release version.

If you want to build the docker image yourself, just run `docker build -t cwe_checker .`

### Local installation ###

The following dependencies must be installed in order to build and install the *cwe_checker* locally:
-   [Rust](https://www.rust-lang.org) >= 1.49
-   [Ghidra](https://ghidra-sre.org/) >= 9.2

Run `make all GHIDRA_PATH=path/to/ghidra_folder` (with the correct path to the local Ghidra installation inserted) to compile and install the *cwe_checker*.

### Local installation with BAP as backend ###

If you want to use the older [BAP](https://github.com/BinaryAnalysisPlatform/bap) backend instead of Ghidra, you must ensure that the following dependencies are fulfilled:
-   Ocaml 4.08.0
-   Opam 2.0.2
-   dune >= 2.0
-   BAP 2.2.0 (and its dependencies).
-   yojson >= 1.6.0
-   ppx_deriving_yojson >= 3.5.1
-   alcotest >= 0.8.3 (for tests)
-   Sark (latest) for IDA Pro annotations
-   pytest >= 3.5.1 (for tests)
-   SCons >= 3.0.5 (for tests)
-   odoc >= 1.4 (for documentation)
-   [Rust](https://www.rust-lang.org) >= 1.49

Just run `make with_bap_backend` to compile and register the plugin with BAP.

## Usage ##

The *cwe_checker* takes a binary as input,
runs several [checks](#checks) based on static analysis on the binary
and then outputs a list of CWE warnings that have been found during the analysis.

If you use the official docker image, just run
```bash
docker run --rm -v /PATH/TO/BINARY:/input fkiecad/cwe_checker /input
```
If you installed the *cwe_checker* locally, run
```bash
cwe_checker BINARY
```
You can adjust the behavior of most checks via a configuration file located at `src/config.json`.
If you modify it, add the command line flag `--config=src/config.json` to tell the *cwe_checker* to use the modified file.
For information about other available command line flags you can pass the `--help` flag to the *cwe_checker*.

If you use the stable version, you can also look at the [online documentation](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html) for more information.

## Documentation and Tests ##

The test binaries for our test suite can be built with `make compile_test_files` (needs Docker to be installed!). The test suite can then be run with `make test`.

Source code documentation can be built with `make documentation`. For the stable version, the documentation can be found [here](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html).

## Implemented Checks <a name=checks></a> ##

So far the following analyses are implemented:
-   [CWE-125](https://cwe.mitre.org/data/definitions/125.html): Out-of-bounds read (via emulation)
-   [CWE-190](https://cwe.mitre.org/data/definitions/190.html): Integer Overflow or Wraparound
-   [CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information
-   [CWE-243](https://cwe.mitre.org/data/definitions/243.html): Creation of chroot Jail Without Changing Working Directory
-   [CWE-332](https://cwe.mitre.org/data/definitions/332.html): Insufficient Entropy in PRNG
-   [CWE-367](https://cwe.mitre.org/data/definitions/367.html): Time-of-check Time-of-use (TOCTOU) Race Condition
-   [CWE-415](https://cwe.mitre.org/data/definitions/415.html): Double Free
-   [CWE-416](https://cwe.mitre.org/data/definitions/416.html): Use After Free
-   [CWE-426](https://cwe.mitre.org/data/definitions/426.html): Untrusted Search Path
-   [CWE-467](https://cwe.mitre.org/data/definitions/467.html): Use of sizeof() on a Pointer Type
-   [CWE-476](https://cwe.mitre.org/data/definitions/476.html): NULL Pointer Dereference
-   [CWE-560](https://cwe.mitre.org/data/definitions/560.html): Use of umask() with chmod-style Argument
-   [CWE-676](https://cwe.mitre.org/data/definitions/676.html): Use of Potentially Dangerous Function
-   [CWE-782](https://cwe.mitre.org/data/definitions/782.html): Exposed IOCTL with Insufficient Access Control

Please note that some of the above analyses only are partially implemented at the moment.
Furthermore, false positives are to be expected due to shortcuts and the nature of static analysis as well as over-approximation.

## Integration into other tools ##

*cwe_checker* comes with a script for Ghidra,
which parses the output of the *cwe_checker* and annotates the found CWEs in the disassembler for easier manual analysis.
The script is located at `ghidra_plugin/cwe_checker_ghidra_plugin.py`, usage instructions are contained in the file.

<p align="center">
    <img src="doc/images/example_ghidra_integration.png" alt="Ghidra Integration" width="90%" height="90%"/>
</p>

## How does cwe_checker work internally? ##

Building the documentation using `cargo doc --open --document-private-items` will give you more information about the internal structure of the *cwe_checker*.
However, the best documentation is still the source code itself.
If you have questions, be sure to ask them on our [discussions page](https://github.com/fkie-cad/cwe_checker/discussions)!
We are constantly striving to improve extensibility and documentation and your questions will help us to achieve that!

To get a quick/initial overview of its internals you can also look at the slides of conference presentations on the *cwe_checker* in the *doc* folder.
We presented cwe_checker at the following conferences so far:
-   [Pass The SALT 2019](https://2019.pass-the-salt.org/talks/74.html) ([slides](doc/slides/cwe_checker_pts19.pdf))
-   [Black Hat USA 2019](https://www.blackhat.com/us-19/arsenal/schedule/index.html#cwe_checker-hunting-binary-code-vulnerabilities-across-cpu-architectures-16782) ([slides](doc/slides/cwe_checker_BlackHatUSA2019.pdf))

### Contribute ###

Contributions are always welcome. Just fork it and open a pull request!

## Acknowledgements ##

This project is partly financed by [German Federal Office for Information Security (BSI)](https://www.bsi.bund.de).

A special thanks goes out to the BAP community (especially the official gitter) for answering questions and discussing solutions.

## License
```
    Copyright (C) 2018 -       Fraunhofer FKIE  (firmware-security@fkie.fraunhofer.de)

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 3 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
```
