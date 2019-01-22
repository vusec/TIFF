#!/bin/sh

cd ../func_detect
make clean
make

cd ../taint_detect
make clean
make
make tools

cd ../tools
#rm -rf howard *.log
