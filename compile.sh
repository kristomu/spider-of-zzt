echo Coordinator
g++ -I/usr/include/libxml2/ src/coordinator.cc src/slurper.cc src/adns/resolved_host.cc -ladns -lcurl -lpthread -lnspr4 -lxml2 -larchive -lmagic -O9 -o coord -ggdb
echo Thread
g++ src/thread.cc src/slurper.cc -ladns -lcurl -lpthread -O9 -o thread -ggdb
echo ZZT_interesting
g++ src/zzt_interest_reader.cc -I/usr/include/libxml2/ -lxml2 -larchive -lmagic -O9 -o zzt_interesting -ggdb
echo uriextract
g++ src/uriextract.cc -lre2 -o uriextract -ggdb
echo "Done!"
