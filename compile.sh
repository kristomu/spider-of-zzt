echo Coordinator
g++ -I/usr/include/libxml2/ src/coordinator.cc src/slurper.cc src/resolved_host.cc src/formats/zzt_interesting.cc -ladns -lcurl -lpthread -lnspr4 -lxml2 -larchive -lmagic -lcrypto -O9 -o coord -ggdb
echo Thread
g++ src/thread.cc src/slurper.cc -ladns -lcurl -lpthread -O9 -o thread -ggdb
echo ZZT_interesting
g++ src/zzt_interest_reader.cc src/formats/zzt_interesting.cc src/filetools.cc -I/usr/include/libxml2/ -lxml2 -larchive -lmagic -lcrypto -O9 -o zzt_interesting -ggdb
echo ZZT_interesting Python 3.9 lib
g++ -shared -o zzt_interesting.so -fPIC src/zzt_interesting_python.cc src/formats/zzt_interesting.cc -I/usr/include/libxml2/ -I/usr/include/python3.9/ -lpython3.9 -lboost_python39 -lxml2 -larchive -lmagic -lcrypto -O9
echo uriextract
g++ src/uriextract_reader.cc src/libvldmail/vldmail.c src/cxxurl/url.cpp src/resolved_host.cc -I/usr/include/libxml2/ -lxml2 -lre2 -o uriextract -ggdb
echo "Done!"
