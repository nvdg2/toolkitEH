#!/bin/bash
pip install twisted
git clone https://gitlab.com/kalilinux/packages/sslstrip.git
chown -R 1000:1000 sslstrip
cd sslstrip
sudo python setup.py install