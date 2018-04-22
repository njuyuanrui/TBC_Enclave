----------------------------
Ucloud-SJTU Blockchain+SGX
----------------------------
The project demonstrates:
- How a remote party attests an application enclave
- How an application enclave generates a RSA public key for a remote party

------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS
2. Make sure your environment is set:
    $ source ${sgx-sdk-install-path}/environment
3. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build: 
        $ make
    b. Hardware Mode, Pre-release build:
        $ make SGX_PRERELEASE=1 SGX_DEBUG=0
    c. Hardware Mode, Release build:
        $ make SGX_DEBUG=0
    d. Simulation Mode, Debug build:
        $ make SGX_MODE=SIM
    e. Simulation Mode, Pre-release build:
        $ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
    f. Simulation Mode, Release build:
        $ make SGX_MODE=SIM SGX_DEBUG=0
4. Execute the binary directly:
    $ ./app
5. Remember to "make clean" before switching build mode

-------------------------------------
Attention
-------------------------------------
gujinyu: 
1. My certificate can only support developer attestation.
2. This demo project does not check the signature revokation list.
3. Work node should run worker enclave. Directory 'provider' is for data
providers.

------------------------------------
Run
------------------------------------
0. install Intel SGX SDK & Driver
1. make
2. ./app  # init the worker enclave and generate the public key
3. cd provider && make 
4. ./provider
