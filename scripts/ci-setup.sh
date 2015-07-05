#!/bin/bash
REPO_SOURCE="deb http://us.archive.ubuntu.com/ubuntu/ utopic main universe"
sudo add-apt-repository $REPO_SOURCE || exit 1
sudo apt-get update -qq || exit 1
sudo apt-get install check cmake -y || exit 1
scripts/install-libsodium.sh || exit 1
