<p align="center">
    <img src="doc/images/cwe_checker_logo.png" alt="cwe_checker logo" width="50%" height="50%"/>
</p>

# cwe_checker #
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/9dbf158110de427d893b40ba397b94bc)](https://www.codacy.com/app/weidenba/cwe_checker?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=fkie-cad/cwe_checker&amp;utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.com/fkie-cad/cwe_checker.svg?branch=master)](https://travis-ci.com/fkie-cad/cwe_checker)
![Docker-Pulls](https://img.shields.io/docker/pulls/fkiecad/cwe_checker.svg)
[![Documentation](https://img.shields.io/badge/doc-stable-green.svg)](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html)

## What is cwe_checker? ##
*cwe_checker* is a suite of tools to detect common bug classes such as use of dangerous functions and simple integer overflows. These bug classes are formally known as [Common Weakness Enumerations](https://cwe.mitre.org/) (CWEs). Its main goal is to aid analysts to quickly find vulnerable code paths.

Its main focus are ELF binaries that are commonly found on Linux and Unix operating systems. *cwe_checker* is built on top of [BAP](https://github.com/BinaryAnalysisPlatform/bap)(Binary Analysis Platform). By using BAP, we are not restricted to one low level instruction set architectures like Intel x86. BAP lifts several of them to one common intermediate representation (IR). cwe_checker implements its analyses on this IR. At time of writing, BAP 1.6 supports Intel x86/x64, ARM, MIPS, and PPC amongst others. Hence, this makes *cwe_checker* a valuable tool for firmware analysis.

*cwe_checker* implements a modular architecture that allows to add new analyses with ease. So far the following analyses are implemented across several BAP plugins:
-   [CWE-125](https://cwe.mitre.org/data/definitions/125.html): Out-of-bounds read (via emulation)
-   [CWE-190](https://cwe.mitre.org/data/definitions/190.html): Integer Overflow or Wraparound
-   [CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information
-   [CWE-243](https://cwe.mitre.org/data/definitions/243.html): Creation of chroot Jail Without Changing Working Directory
-   [CWE-248](https://cwe.mitre.org/data/definitions/248.html): Uncaught Exception
-   [CWE-332](https://cwe.mitre.org/data/definitions/332.html): Insufficient Entropy in PRNG
-   [CWE-367](https://cwe.mitre.org/data/definitions/367.html): Time-of-check Time-of-use (TOCTOU) Race Condition
-   [CWE-426](https://cwe.mitre.org/data/definitions/426.html): Untrusted Search Path
-   [CWE-457](https://cwe.mitre.org/data/definitions/457.html): Use of Uninitialized Variable
-   [CWE-467](https://cwe.mitre.org/data/definitions/467.html): Use of sizeof() on a Pointer Type
-   [CWE-476](https://cwe.mitre.org/data/definitions/476.html): NULL Pointer Dereference
-   [CWE-560](https://cwe.mitre.org/data/definitions/560.html): Use of umask() with chmod-style Argument
-   [CWE-676](https://cwe.mitre.org/data/definitions/676.html): Use of Potentially Dangerous Function
-   [CWE-782](https://cwe.mitre.org/data/definitions/782.html): Exposed IOCTL with Insufficient Access Control

**NOTE:** We recently decided to deprecate the support for the emulation based checks for CWEs 415, 416 and 787. Users of these checks should take a look at the [BAP toolkit](https://github.com/BinaryAnalysisPlatform/bap-toolkit), which provides better-maintained versions of these checks.

Please note that some of the above analyses only are partially implemented at the moment. Furthermore, false positives are to be expected due to shortcuts and the nature of static analysis as well as over-approximation. For more information about the individual checks you can look at the [online documentation](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html).

*cwe_checker* comes with scripts for IDA Pro and Ghidra, which parse the output of *cwe_checker* and annotate the found CWEs in the disassembler for easier manual analysis. See the [online documentation](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html#ToolIntegration) for their usage. The IDA Pro plugin also uses colors to represent the  severeness of the found issues (yellow, orange, or red). The following screenshot shows some results:

<p align="center">
    <img src="doc/images/example_ida_anotation.png" alt="IDA Pro anotation" width="50%" height="50%"/>
</p>

## Why use cwe_checker? ##
The following arguments should convince you to give *cwe_checker* a try:
-  it is very easy to setup, just build the Docker container!
-  it analyzes ELF binaries of several CPU architectures including x86, ARM, MIPS, and PPC
-  it is extensible due to its plugin-based architecture
-  it is configureable, e.g. apply analyses to new APIs
-  view results annotated in IDA Pro and Ghidra
-  *cwe_checker* can be integrated as a plugin into [FACT](https://github.com/fkie-cad/FACT_core)

## How to install cwe_checker? ##
There are several ways to install cwe_checker. The recommended way is to get cwe_checker from the Ocaml package manager Opam. You can install cwe_checker via the package [cwe_checker](https://opam.ocaml.org/packages/cwe_checker/) (`opam install cwe_checker`). This gives you a stable version of cwe_checker.

Another option is to pull the latest Docker image from [dockerhub](https://hub.docker.com/r/fkiecad/cwe_checker):
-   `docker pull fkiecad/cwe_checker:latest` yields an image based on the current master branch.
-   `docker pull fkiecad/cwe_checker:stable` yields an image based on the latest stable release version.

If you plan to develop cwe_checker, it is recommended to build it using the provided `Makefile`. In this case you must ensure that all dependencies are fulfilled:
-   Ocaml 4.07.1
-   Opam 2.0.2
-   dune >= 1.6
-   BAP (and its dependencies). Development on the master branch depends on the master branch of BAP which can be added with `opam repo add bap-testing git+https://github.com/BinaryAnalysisPlatform/opam-repository#testing` to the sources of the Opam package manager. The stable release of the *cwe_checker* depends on BAP 1.6.
-   yojson >= 1.6.0
-   ppx_deriving_yojson >= 3.5.1
-   alcotest >= 0.8.3 (for tests)
-   Sark (latest) for IDA Pro annotations
-   pytest >= 3.5.1 (for tests)
-   SCons >= 3.0.5 (for tests)
-   odoc >= 1.4 (for documentation)

Just run `make all` to compile and register the plugin with BAP. You can run the test suite via `make test`. Documentation can be built via `make documentation`.

## How to use cwe_checker? ##
The usage is straight forward: adjust the `config.json` (if needed) and call BAP with *cwe_checker* as a pass.
``` bash
bap PATH_TO_BINARY --pass=cwe-checker --cwe-checker-config=src/config.json
```
For further information see the [online documentation](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html). You can also build the documentation locally via `make documentation` and then browse it in the *doc/html/* folder.

## How to extend cwe_checker? ##
You can find some information about how to write your own check [here](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html#HackingHowto)

If you plan to open a PR, please utilize [precommit](https://pre-commit.com) in your development environment to catch many issues before the code review.

### Contribute ###
Contributions are always welcome. Just fork it and open a pull request!

## How does cwe_checker work internally? ##
See the [online documentation](https://fkie-cad.github.io/cwe_checker/doc/html/cwe_checker/index.html) or build it locally via `make documentation` and then browse it in the *doc/html/* folder. But the most accurate documentation is still the source code. We also provide some slides of conference presentations on cwe_checker in *doc*. These should be of special interest for those who would like to get a quick/initial overview of its internals.

We presented cwe_checker at the following conferences so far:
-   [Pass The SALT 2019](https://2019.pass-the-salt.org/talks/74.html) ([slides](doc/slides/cwe_checker_pts19.pdf))
-   [Black Hat USA 2019](https://www.blackhat.com/us-19/arsenal/schedule/index.html#cwe_checker-hunting-binary-code-vulnerabilities-across-cpu-architectures-16782) ([slides](doc/slides/cwe_checker_BlackHatUSA2019.pdf))

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
