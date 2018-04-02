###### fireice-uk's and psychocrypt's
###### Ported by nioroso-x3
# XMR-Stak - Monero/Aeon All-in-One Mining Software

XMR-Stak is a universal Stratum pool miner. This miner supports CPUs, with AMD and NVIDIA gpus untested and can be used to mine the crypto currency Monero and Aeon.

## Overview

* [Features](#features)
* [Supported altcoins](#supported-altcoins)
* [Linux Portable Binary](doc/Linux_deployment.md)
* [Usage](doc/usage.md)
* [HowTo Compile](doc/compile.md)
* [FAQ](doc/FAQ.md)
* [Developer Donation](#default-developer-donation)

## Features

- support CPU backend, GPUs untested (CPU/ppc64le, AMD-GPU and NVIDIA-GPU)
- Linux only
- supports algorithm cryptonight for Monero (XMR) and cryptonight-light (AEON)
- easy to use
  - guided start (no need to edit a config file for the first start)
  - auto configuration for each backend
- open source software (GPLv3)
- TLS support
- [HTML statistics](doc/usage.md#html-and-json-api-report-configuraton)
- [JSON API for monitoring](doc/usage.md#html-and-json-api-report-configuraton)

## Supported altcoins

Besides [Monero](https://getmonero.org), following coins can be mined using this miner:

- [Aeon](http://www.aeon.cash)
- [Edollar](https://edollar.cash)
- [Electroneum](https://electroneum.com)
- [Graft](https://www.graft.network)
- [Intense](https://intensecoin.com)
- [Karbo](https://karbo.io)
- [Sumokoin](https://www.sumokoin.org)

If your prefered coin is not listed, you can chose one of the following algorithms:

- Cryptonight - 2 MiB scratchpad memory
- Cryptonight-light - 1 MiB scratchpad memory

Please note, this list is not complete, and is not an endorsement.

## Default Developer Donation

By default the miner will donate 0.88% of the hashpower (53 seconds in 100 minutes) to my pool. If you want to change that, edit [donate-level.hpp](xmrstak/donate-level.hpp) before you build the binaries.

If you want to donate directly to support further development, here is my wallet

nioroso-x3:
```
42UwBFuWj9uM7RjH15MXAFV7oLWUC9yLTArz4bmD3gbVWu1obYRUDe8K9v8StqXPhP2Uz1BJZgDQTUVhvT1cHFMBHA6aPg2
```

fireice-uk:
```
4581HhZkQHgZrZjKeCfCJxZff9E3xCgHGF25zABZz7oR71TnbbgiS7sK9jveE6Dx6uMs2LwszDuvQJgRZQotdpHt1fTdDhk
```

psychocrypt:
```
45tcqnJMgd3VqeTznNotiNj4G9PQoK67TGRiHyj6EYSZ31NUbAfs9XdiU5squmZb717iHJLxZv3KfEw8jCYGL5wa19yrVCn
```
