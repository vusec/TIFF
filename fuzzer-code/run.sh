#!/bin/sh
echo $1
#for file in * 
#do
echo $2 $1
cwd=$PWD
cd ../tools
./clean
python howard.py $2 $1
python combine_offset.py
python a.py
cd $cwd
cp ../tools/cmp.out .
cp ../tools/lea.out .
cp ../tools/err_offset.json .
cp ../tools/err_arr_offset.json .
cp ../tools/reward.taint .
