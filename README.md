# [Eccologic ASM](https://asm.eccologic.net/) 🌐
Provides a web server that allows for x86/AArch64 assembling & disassembling through a RESTful API and serves a Single-page application (SPA) website for clients to program in.

### Why?
Well... because it was fun. While other websites like this exist (and some are even better), I wanted to take my own approach to it and make it open source.

## Building & Usage 🔨👷
The preferred way to use this project with little hassle is to just use [Docker](https://www.docker.com/). I've provded a `Dockerfile` and `docker-compose.yml` for that reason.

This project is only tested and working on Windows (Windows 10 w/ MSVC) & Linux (Debian (Bullseye) w/ GCC).\
The web server currently only serves over HTTP (Port `80` by default) and does **not** rate limit. Ideally you'd run this all behind a reverse proxy and configure rate limits, etc yourself.
If someone wants to contribute and add HTTPS support then go right ahead.

Prerequisites:
* [Git](https://git-scm.com/downloads)
* [Node.js](https://nodejs.org/en/download/)
* A C++20 ready compiler.

Oh and for Linux, you'll need `bash` too.

If you haven't already, clone the repository into some directory.
```cmd
> git clone https://github.com/angelfor3v3r/eccologic-asm.git
```

To build for Windows:
```cmd
> cd eccologic-asm/backend
> ./build.bat
```

To build for Linux:
```cmd
> cd eccologic-asm/backend
> ./build.sh
```

And finally, you need to build the frontend:
```cmd
> cd eccologic-asm/frontend
> npm install
> npm run build
```

Once finished, you'll end up with a `bin` folder in `eccologic-asm`.

* On Windows, you can just run the `asm.exe`.
* On Linux you **MUST** run the binary with `libmimalloc` like so: `env LD_PRELOAD=/eccologic-asm/bin/libmimalloc.so /eccologic-asm/bin/asm`.

If all went well then the website will be accessible from port `80`! 🎉

## Credits ❤️
* [Angelfor3v3r](https://github.com/angelfor3v3r) - Creator & Lead programmer.
* [JosiahWhite](https://github.com/JosiahWhite) - Frontend programming help.
* [Dom](https://github.com/domve) - General help & Library recommendations.

... And an additional thank you to all the amazing creators & contributors from the following projects:
* [Drogon](https://github.com/drogonframework/drogon)
* [{fmt}](https://github.com/fmtlib/fmt)
* [mimalloc](https://github.com/microsoft/mimalloc)
* [Keystone](https://github.com/keystone-engine/keystone)
* [Capstone](https://github.com/aquynh/capstone)
* [Vcpkg](https://github.com/microsoft/vcpkg)
* [CMake](https://github.com/Kitware/CMake)
* [Docker](https://github.com/docker)
* [Node.js](https://github.com/nodejs/node)
* [npm](https://github.com/npm/cli)
* [Webpack](https://github.com/webpack/webpack)
* [Preact](https://github.com/preactjs/preact)
* [Bootstrap](https://github.com/twbs/bootstrap)
* [bootswatch](https://github.com/thomaspark/bootswatch/)
* [CodeMirror](https://github.com/codemirror/CodeMirror)

None of this would've been possible without you! Thank you for all your work.