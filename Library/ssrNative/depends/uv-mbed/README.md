## Overview
UV-MBED is a cross-platform library allowing asynchronous TLS communication. 
This is done by combinining [libuv](https://github.com/libuv/libuv) with [mbedTLS](https://github.com/ARMmbed/mbedtls.git)

### Features
* async TLS over TCP

### API
API is attempted to be consistent with [libuv API](http://docs.libuv.org/en/v1.x/api.html)

### Suuported Platforms
* Linux
* Darwin/MacOS
* Windows

## Build
```
git clone https://github.com/ShadowsocksR-Live/uv-mbed.git
cd uv-mbed
git submodule update --init
mkdir build
cd build
cmake .. && make

```

## Test
```
# test url https://mh-nexus.de/downloads/HxDSetup.zip
sample/sample -s mh-nexus.de -p 443 -r /downloads/HxDSetup.zip -o a.zip

```
