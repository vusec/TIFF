

### Installation ###

* Installing EWAHBoolArray  https://github.com/lemire/EWAHBoolArray/ - To install it in your system just copy headers file(https://github.com/lemire/EWAHBoolArray/tree/master/headers) in /usr/include folder.
* BitVector is also one of the dependencies of the project. It can be installed  using "pip install BitVector"
* Now we would need to generate the names and pkl files of the binary using IDA Disassembler. Please use the BB-weight4.py (present in fuzzer-code/ directory) in the IDA disassembler. This script would create the necessary pkl and names files of the binary. (This step need to be repeated for each binary) To run on IDA, we would first need to load the binary in IDA, Then there is an option in IDA to run the script on the disassembled binary. 
* After generating the pkl and name files, copy them to the fuzzer-code/idafiles folder.
* Please set the following env variables PIN_HOME and PIN_ROOT to the directory location of pin-2.13 
* After this go to func_detect, and run 'make'
* After this go to libdft64 and run 'make' followed by 'make tools'
* After this go to taint_detect and run 'make' followed by 'make tools'
* Now go to fuzzer-code and run following command
* make -f mymakefile
* echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
* echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
* sudo mount -t tmpfs -o size=1024M tmpfs vutemp

## Running Fuzzer ##
* runfuzzer.py [-h] -s SUT -i INPUTD -w WEIGHT -n NAME [-l LIBNUM] -o
                    OFFSETS [-b LIBNAME]
For example, if we want to fuzz 'uniq' binary, following is the command:
* python runfuzzer.py -s "<path_to_uniq_binary> %s" -i datatemp/uniq/ -w idafiles/uniq.pkl -n idafiles/uniq.names -l 1 -o "0x0000000000000000"

## Further information ##
1. Check out README-dataSet.md to know more about the dataset used in evaluating TIFF and setting of configuration parameters.
2. Check out (historic) wikiHOWTO.md to know more information about various parameters that have some impact on the fuzzer's performance.  
## Important Note ##
The code is not cleaned properly yet, but it works! We will clean it in the near future. Currently, one of the lead authors is relocating to another country and other is engaged in his new job. As a result, we'll not be in a position to address issues immediately, but we'll try our best to work on them when time permits. Please don't shoot us!
