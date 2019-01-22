#!/bin/sh
echo $1
echo $2 $1
cwd=$PWD
cd ../libdft64/tools
./clean
$PIN_HOME/pin.sh -t libdft-dta.so -filename $2 -maxoff 1 -x $3 -- $1
python a.py
cd $cwd
cp ../libdft64/tools/cmp.out .
cp ../libdft64/tools/lea.out .
cp ../libdft64/tools/err_offset.json .
cp ../libdft64/tools/err_arr_offset.json .
cp ../libdft64/tools/reward.taint .
