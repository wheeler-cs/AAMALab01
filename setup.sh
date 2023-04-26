#!/bin/bash

# Install needed Python libraries
pip install -r requirements.txt

# Download executables needed for assignment
# TODO: Use wget or something like it to download some executables

# Remove residule git artifacts
rm -rf .git
rm .gitignore
rm setup.sh