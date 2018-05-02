Provider_Files:=Provider.cpp Verify.cpp
Util_Files:=Util/WebService.cpp Util/Check.cpp Util/UtilityFunctions.cpp Util/Base64.cpp Util/LogBase.cpp Util/GetMeasurement.cpp
CXX_Flags:=-std=c++11 -I./include -IUtil -L/usr/local/lib -L/usr/local/lib64 -L/usr/lib64
CXX_Link_Flags:=-llog4cpp -lnsl -lrt -lpthread -lz -lboost_system -lssl -lcrypto -lboost_thread -lprotobuf -ljsoncpp -lcurl

libprovider.so: $(Provider_Files) $(Util_Files)
	@g++ $(CXX_Flags) -shared -o $@ $^ $(CXX_Link_Flags)

main:main.cpp
	@g++ $^ -o $@ -I./include -L. -lprovider

.PHONY: clean
clean:
	rm -f provider .tmp* Util/*.o
