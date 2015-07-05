#!/bin/bash
sudo add-apt-repository "deb http://us.archive.ubuntu.com/ubuntu/ utopic main universe"
sudo apt-get update -qq
sudo apt-get install check cmake
scripts/install-libsodium.sh
