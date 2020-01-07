# OpenSSH SK API implemented with Intel SGX

Treat the Intel SGX as a FIDO-like authenticator:
Generate private ED25519-SK keys on a stateless SGX enclave.
Private keys are sealed by the enclave and stored in the key handle
of the ED25519-SK key. Only the enclave can un-seal such a private key.

The file `sk-sgx.c` implements the `SSH_SK_PROVIDER` for OpenSSH,
`enclave.c` the matching SGX enclave.  The interface
between provider and enclave is specified in `sk.edl`.

## Install Ubuntu 18.04

See https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/HyperVLinuxVMSetup.md
for running Ubuntu with SGX on HyperV.

## Install SDK

* https://01.org/intel-software-guard-extensions/downloads
* https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/
* https://download.01.org/intel-sgx/sgx-linux/2.7.1/docs/Intel_SGX_Installation_Guide_Linux_2.7.1_Open_Source.pdf

## Build provider and enclave

	% source /home/ubuntu/sgxsdk/environment
	% make
or

	% make SK_DEBUG=1

Use the resulting `sk-sgx.so` library as the SSH_SK_PROVIDER.
It will execute `enclave.signed.so` in the SGX enclave.

	% SSH_SK_PROVIDER=./sk-sgx.so /home/ubuntu/ssh/bin/ssh-keygen -t ed25519-sk
	% SSH_SK_PROVIDER=./sk-sgx.so /home/ubuntu/ssh/bin/ssh host

If you don't have SGX hardware, you can use the simulator:

	% make SGX_MODE=SIM

If you want to use run sk-sgx standalone without OpenSSH:

	% make SGX_MODE=SIM SK_DEBUG=1 TEST=1
	% ./sk-sgx.so

-m
