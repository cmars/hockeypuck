#!/bin/bash

set -eu

sudo apt-get update
sudo apt-get install -y docker.io docker-compose fail2ban
sudo gpasswd -a ubuntu docker

