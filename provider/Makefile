Provider_Files:=Provider.cpp Verify.cpp
Util_Files:=Util/WebService.cpp Util/Check.cpp Util/UtilityFunctions.cpp Util/Base64.cpp Util/LogBase.cpp Util/GetMeasurement.cpp
CXX_Flags:=-std=c++11 -I. -IUtil
CXX_Link_Flags:=-llog4cpp -lboost_system -lssl -lcrypto -lboost_thread -lprotobuf -ljsoncpp -lcurl

provider: $(Provider_Files) $(Util_Files)
	@g++ $(CXX_Flags) -o $@ $^ $(CXX_Link_Flags)


.PHONY: clean
clean:
	rm -f provider .tmp* Util/*.o
