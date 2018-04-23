Provider_Files:=Provider.cpp Verify.cpp
Util_Files:=Util/WebService.cpp Util/Check.cpp Util/UtilityFunctions.cpp Util/Base64.cpp Util/LogBase.cpp Util/GetMeasurement.cpp
CXX_Flags:=-std=c++11 -I. -IUtil -L/usr/local/lib -L/usr/local/lib64 -L/usr/lib64
CXX_Link_Flags:=-llog4cpp -lnsl -lrt -lpthread -lz -lboost_system -lssl -lcrypto -lboost_thread -lprotobuf -ljsoncpp -lcurl

provider: $(Provider_Files) $(Util_Files)
	@g++ $(CXX_Flags) -o $@ $^ $(CXX_Link_Flags)


.PHONY: clean
clean:
	rm -f provider .tmp* Util/*.o
