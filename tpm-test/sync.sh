#!/bin/bash
echo "Send to XPS1"

rsync -a --info=progress2 . jetli@XPS1:/home/jetli/sgx-learning/project/SGX_BRAFT/TPM-things/tpm-test
echo "Send to XPS2"

rsync -a --info=progress2 . jetli@XPS2:/home/jetli/sgx-learning/project/SGX_BRAFT/TPM-things/tpm-test

