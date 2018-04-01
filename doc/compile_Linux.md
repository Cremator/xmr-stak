# Compile **xmr-stak** for Linux

## Install Dependencies

### OpenCL

AMD ROCm should compile, but I cannot test it due to lack of hardware.

### Cuda 8.0+ (only needed to use NVIDIA GPUs)

- download and install [https://developer.nvidia.com/cuda-downloads](https://developer.nvidia.com/cuda-downloads)
- for minimal install choose `Custom installation options` during the install and select
    - CUDA/Develpment
    - CUDA/Runtime
    - Driver components

### GNU Compiler
```
    # Ubuntu
    sudo apt install libmicrohttpd-dev libssl-dev cmake build-essential libhwloc-dev
    #install IBM developer tools or compile gcc 6.3.x yourself
    git clone https://github.com/fireice-uk/xmr-stak.git
    mkdir xmr-stak/build
    cd xmr-stak/build
    cmake ..
    make install

    # CentOS
    sudo yum install centos-release-scl epel-release
    sudo yum install cmake3 hwloc-devel libmicrohttpd-devel openssl-devel make
    #install IBM developer tools or compile gcc 6.3.x yourself
    git clone https://github.com/fireice-uk/xmr-stak.git
    mkdir xmr-stak/build
    cd xmr-stak/build
    cmake3 ..
    make install

```

- IBM g++ version 6.3 or higher is required for full Altivec and C++11 support. 
If you want to compile the binary without installing libraries / compiler or just compile binary for some other distribution, please check the [build_xmr-stak_docker.sh script](scripts/build_xmr-stak_docker/build_xmr-stak_docker.sh).

### To do a generic and static build for a system without gcc 6.3+
```
    cmake -DCMAKE_LINK_STATIC=ON -DXMR-STAK_COMPILE=generic .
    make install
    cd bin\Release
    copy C:\xmr-stak-dep\openssl\bin\* .
```
Note - cmake caches variables, so if you want to do a dynamic build later you need to specify '-DCMAKE_LINK_STATIC=OFF'
