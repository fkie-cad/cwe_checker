#!/bin/bash
docker run --rm -t cwe-checker make codestyle-check \
&& docker run --rm -t cwe-checker cargo test \
&& docker run --rm -t cwe-checker dune runtest \
&& pytest
