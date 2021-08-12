@echo off
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019" -T host=x64 -A x64 -DCMAKE_BUILD_TYPE="Release"
cmake --build . --config "Release"