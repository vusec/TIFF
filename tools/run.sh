#top_dir="/root/Ashish/dtracker/dtracker/datatemp/pcap"
#cd $top_dir
echo $1 $2
#for file in * 
#do
echo $file
cd /root/vusec-howard-5ee0b83beb89/tools
./clean
python howard.py $2 $1
python combine_offset.py
python a.py
cd /root/vusec-howard-5ee0b83beb89/fuzzer-code
cp ../tools/cmp.out .
#cd /root/vusec-howard-5ee0b83beb89/tools/tcp_exper
#  echo `pwd`
#  mkdir $file
#  cd $file
#  echo `pwd`
#  mv ../../howard .
#  mv ../../*.json .
#  cd $top_dir
#done
