# Breaking WEP - WEP Protocol Security Analysis

This project is a C++ implementation focused on analyzing and demonstrating security vulnerabilities in the WEP (Wired Equivalent Privacy) protocol. It includes various attack implementations and cryptographic analysis tools.

## Project Overview

This diploma work project implements several known attacks against the WEP protocol, including:
- RC4 stream cipher analysis
- Klein's attack
- Tews-Weinmann-Pyshkin attack methods

## Technical Details

### Project Structure
- `Attack.h/cpp`: Core attack implementation interfaces and base classes
- `Crypto.h/cpp`: Cryptographic primitives and utilities
- `RC4.h/cpp`: Implementation of the RC4 stream cipher
- `Klein.h/cpp`: Implementation of Klein's attack on WEP
- `TewsWeinmannPyshkin.h/cpp`: Implementation of the TWP attack methodology
- `StreamTWP.h/cpp`: Stream processing for TWP attack

### Build Configuration
- Visual Studio solution (VS 2015)
- Supports both x86 and x64 architectures
- Multiple build configurations:
  - Debug
  - Release
  - FasterAttack (optimized for attack performance)

### System Requirements
- Windows operating system
- Visual Studio 2015 or later
- C++ compiler with C++11 support

## Building the Project

1. Open `BreakingWEP.sln` in Visual Studio
2. Select desired build configuration (Debug/Release/FasterAttack)
3. Select target platform (x86/x64)
4. Build the solution

## Usage

The program implements two main attack methods:
1. Klein's Attack
2. Modified Klein's Attack
3. Tews-Weinmann-Pyshkin (TWP) Attack

### Example Usage
```cpp
// Example of using the Klein attack with direct data input
size_t keySize = 13; // key size in bytes
auto data = parse_data( "data.txt" ); // parse data from file
std::unique_ptr<Attack> att = std::make_unique<Klein>( data, keySize ); // create attack object
Key rootKey = att->find_key(); // find key
```


## Implementation Details

The project implements several key components:
- Stream cipher cryptanalysis
- Key recovery attacks
- Permutation analysis
- Statistical attack methods

## Academic Context

This project was developed as a diploma work in 2017, focusing on wireless network security, specifically analyzing vulnerabilities in the WEP protocol. It demonstrates practical implementations of theoretical attack vectors against WEP encryption.

## Disclaimer

This project is for academic and research purposes only. The implementation of these attacks is intended to demonstrate and study security vulnerabilities. Do not use this software for attacking real networks or any malicious purposes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 