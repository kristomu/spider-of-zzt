echo Coordinator
g++ src/coordinator.cc src/slurper.cc -ladns -lcurl -lpthread -O9 -o coord
echo Thread
g++ src/thread.cc src/slurper.cc -ladns -lcurl -lpthread -O9 -o thread
echo ZZT_interesting
g++ src/zzt_interesting.cc -I/usr/include/libxml2/ -lxml2 -larchive -lmagic -O9 -o zzt_interesting
echo "Done!"
