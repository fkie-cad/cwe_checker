# cwe_checker #
## What is cwe_checker? ## 
*cwe_checker* detects common bug classes such as use of dangerous functions and simple integer overflows. These bug classes are formally known as [Common Weakness Enumerations](https://cwe.mitre.org/) (CWEs). Its main goal is to aid analysts to quickly find vulnerable code paths.

Its main focus are ELF binaries that are commonly found on Linux and Unix operating systems. *cwe_checker* is built on top of [BAP](https://github.com/BinaryAnalysisPlatform/bap)(Binary Analysis Platform). By using BAP, we are not restricted to one low level instruction set architectures like Intel x86. BAP lifts several of them to one common intermediate represenetation (IR). cwe_checker implements its analyses on this IR. At time of writing, BAP 1.5 supports Intel x86/x64, ARM, MIPS, and PPC amongst others. Hence, this makes *cwe_checker* a valuable tool in firmware analysis.

*cwe_checker* implements a modular architecture that allows to add new analyses with ease. So far the following analyses are implemented:
- [CWE-190](https://cwe.mitre.org/data/definitions/190.html): Integer Overflow or Wraparound
- [CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information 
- [CWE-243](https://cwe.mitre.org/data/definitions/243.html): Creation of chroot Jail Without Changing Working Directory
- [CWE-332](https://cwe.mitre.org/data/definitions/332.html): Insufficient Entropy in PRNG
- [CWE-367](https://cwe.mitre.org/data/definitions/367.html): Time-of-check Time-of-use (TOCTOU) Race Condition
- [CWE-426](https://cwe.mitre.org/data/definitions/426.html): Untrusted Search Path
- [CWE-457](https://cwe.mitre.org/data/definitions/457.html): Use of Uninitialized Variable
- [CWE-467](https://cwe.mitre.org/data/definitions/467.html): Use of sizeof() on a Pointer Type
- [CWE-476](https://cwe.mitre.org/data/definitions/476.html): NULL Pointer Dereference
- [CWE-676](https://cwe.mitre.org/data/definitions/676.html): Use of Potentially Dangerous Function
- [CWE-782](https://cwe.mitre.org/data/definitions/782.html): Exposed IOCTL with Insufficient Access Control

Please note that some of the above analyses only are partially implemented at the moment. Furthermore, false positives are to be expected due to shortcuts and the nature of static analysis.

*cwe_checker* comes with a script called `cwe_checker_to_ida`, which parses the output of *cwe_checker* and generates a IDAPython script. This script annotates the found CWEs in IDA Pro, which helps during manual analysis of a binary. The following screenshot shows some results:
![](https://github.com/fkie-cad/cwe_checker/raw/master/doc/images/example_ida_anotation.png =400x)
## Why use cwe_checker? ##
The following arguments should convince you to give *cwe_checker* a try:
- it is very easy to setup, just build the Docker container!
- it analyzes ELF binaries of several CPU architectures including x86, ARM, MIPS, and PPC
- it is extensible due to its plugin-based architecture
- it is configureable, e.g. apply analyses to new APIs
- view results annotated in IDA Pro
- *cwe_checker* can be integrated as a plugin into [FACT](https://github.com/fkie-cad/FACT_core) 
## How to install cwe_checker? ##
There are two ways to install cwe_checker. The recommended way is to utilize the installation script `install.sh`, which is just a wrapper around Docker. Make sure to have the latest version of Docker. 

The second way is to build it using the provided `Makefile`. In this case you must ensure that all dependencies are fulfilled:
- Ocaml 4.05.0
- Opam 1.2.2
- BAP 1.5 (and its dependencies)
- yojson 1.4.1
- alcotest 0.8.3
- Sark for IDA Pro annotations
Just run `make all` to compile and register the plugin with BAP.
## How to use cwe_checker? ##
The usage is straight forward: adjust the `config.json` (if needed) and call BAP with *cwe_checker* as a pass.
``` bash
bap PATH_TO_BINARY --pass=cwe-checker --cwe-checker-config=src/config.json
```
*cwe_checker* outputs to stdin. This output is parsable (sexep). There is a script `cwe_checker_to_ida` to visualize the results in IDA Pro.
## How to extend cwe_checker? ##
New plugins should be added to src/checkers. Implement a .ml and .mli file. See the existing modules for an interface description. If necessary add a section to `config.json` to allow users to configure your plugin. Finally, add your plugin to `cwe_checker.ml`.
### Contribute ###
Contributions are always welcomed. Just fork it and open a pull request!
## Acknowledgements ##
This project is partly financed by [German Federal Office for Information Security (BSI)](https://www.bsi.bund.de).

A special thanks goes out to the BAP community (especially the official gitter) for answering questions and discussing solutions. 
## License
```
    Copyright (C) 2018 -      Fraunhofer FKIE  (thomas.barabosch@fkie.fraunhofer.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    Some plug-ins may have different licenses. If so, a license file is provided in the plug-in's folder.
```
