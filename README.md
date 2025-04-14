# DNTAT

## DNTAT_pyhton
> Proof-of-concept implementation of anonymous tokens with decentralized issuance.

### Testing

To run the smart contract test (requires [Foundry](https://book.getfoundry.sh/getting-started/installation)), execute:

```sh
forge test
```

To run the Python test (requires [Poetry](https://python-poetry.org/docs/)), execute:

```sh
cd py
poetry shell
poetry install
maturin develop --release
python -m unittest *.py
```

### Benchmarks

To run the smart contract gas benchmarks (requires [Foundry](https://book.getfoundry.sh/getting-started/installation) and [Poetry](https://python-poetry.org/docs/)), execute:

```sh
cd py
poetry shell
poetry install
maturin develop --release
NUM_SIGNERS=8 python generate-tokens.py && forge test --mc DNTAT_PS --gas-report
```

## DNTAT_redemption_mcl

> implementations of token redemption process in C++ using the mcl library.

### How to build on Linux and macOS

x86-64/ARM/ARM64 Linux, macOS and mingw64 are supported.

GMP is necessary only to build test programs.

- `sudo apt install libgmp-dev` on Ubuntu
- `brew install gmp` on macOS

OpenMP is optional (`make MCL_USE_OMP=1` to use OpenMP for `mulVec`)

- `sudo apt install libomp-dev` on Ubuntu
- `brew install libomp`

### How to build with Makefile

For x86-64 Linux and macOS,

```sh
git clone https://github.com/herumi/mcl
cd mcl
make -j4
```

clang++ is required except for x86-64 on Linux and Windows.

```sh
make -j4 CXX=clang++
```

- `lib/libmcl.*` ; core library
- `lib/libmclbn384_256.*` ; library to use C-API of BLS12-381 pairing
