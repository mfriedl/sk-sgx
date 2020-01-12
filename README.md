# OpenSSH SK API implemented with Intel SGX

Treat the Intel SGX as a FIDO-like authenticator:
Generate private ED25519-SK keys on a stateless SGX enclave.
Private keys are sealed by the enclave and stored in the key handle
of the ED25519-SK key. Only the enclave can un-seal such a private key.

The file `sk-sgx.c` implements the `SSH_SK_PROVIDER` for OpenSSH,
`enclave.c` the matching SGX enclave.  The interface
between provider and enclave is specified in `sk.edl`.

This code can be used to protect private SSH host keys, for example.
If SGX is supported by the virtual machine, then the private key
will also be hidden from the cloud provider.

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

Use the resulting `sk-sgx.so` library as the `SSH_SK_PROVIDER`.
It will execute `enclave.signed.so` in the SGX enclave.

	% SSH_SK_PROVIDER=./sk-sgx.so /home/ubuntu/ssh/bin/ssh-keygen -t ed25519-sk
	% SSH_SK_PROVIDER=./sk-sgx.so /home/ubuntu/ssh/bin/ssh host

If you don't have SGX hardware, you can use the simulator:

	% make SGX_MODE=SIM

If you want to use run sk-sgx standalone without OpenSSH:

	% make SGX_MODE=SIM SK_DEBUG=1 TEST=1
	% ./sk-sgx.so

## WARNING

If you sign `enclave.so` with a different `private.pem`, then the
`MRSIGNER` measurement changes and the private keys can no longer be
decryped.

## Notes

* SGX intro: https://blog.quarkslab.com/overview-of-intel-sgx-part-1-sgx-internals.html
* SGX details: https://eprint.iacr.org/2016/086.pdf
* emulated instructions in SDK: sdk/simulation/tinst/t_instructions.cpp
* Foreshadow (spectre): https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-van_bulck.pdf
* SCONE (container): https://www.usenix.org/system/files/conference/osdi16/osdi16-arnautov.pdf

-m
