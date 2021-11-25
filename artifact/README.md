Artifact for HardsHeap
======================

Setup
-----
For testing, we need to build secure allocators. This is automatically done
when you build a Docker image. If you want to run HardsHeap in your native
environment, please do

```sh
$ ./build.sh
```

Launch
------
For your convenience, we provide a script, `run.py` for running HardsHeap.

Here is a help text for `run.py`
```sh
$ ./run.py -h

usage: run.py [-h] [-t TIMEOUT] -r ROOT_DIR [-b BUILD_DIR] -o OUTPUT_DIR [-m MODULE] [-a ALLOCATOR]

optional arguments:
  -h, --help            show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT
  -r ROOT_DIR, --root_dir ROOT_DIR
                        HardsHeap's root directory
  -b BUILD_DIR, --build_dir BUILD_DIR
                        Build directory with compiled modules
  -o OUTPUT_DIR, --output_dir OUTPUT_DIR
                        Output directory to store testing results
  -m MODULE, --module MODULE
                        HardsHeap module to run (Default: all modules)
  -a ALLOCATOR, --allocator ALLOCATOR
                        Secure allocator (Default: all allocators)
```

For example, if you want to run adjacent module to DieHarder,
```
$ ./run.py  -r $(pwd)/../ -o output -a DieHarder-6cf204ec -m adjacent
```

Minimization
------------
For minimization, we have provided a script, `minimize.py`.
```sh
$ ./minimize.py -h
usage: minimize.py [-h] [-t TIMEOUT] -r ROOT_DIR -o OUTPUT_DIR -m MODES [MODES ...]

optional arguments:
  -h, --help            show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT
  -r ROOT_DIR, --root_dir ROOT_DIR
                        HardsHeap's root directory
  -o OUTPUT_DIR, --output_dir OUTPUT_DIR
                        Output directory
  -m MODES [MODES ...], --modes MODES [MODES ...]
                        Modes for minimization (ssdd, greedy, deterministic)
```

For example, if you want to minimize test cases with Statistical Significance
Delta Debugging (SSDD),
```sh
$ ./minimize.py  -r $(pwd)/../ -o output/  -m ssdd
```

Then, you can find a minimized PoC code in `minimize_ssdd` of the output directory. For example,
```
$ cat output/adjacent/output-DieHarder-6cf204ec/minimize_ssdd/id\:000000*.log
// Disable capability: HEAP_WRITE
// Disable capability: BUFFER_WRITE
// Disable capability: VULN
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>

void* p[256];
uintptr_t buf[256];

int main() {
  // [INFO] Stream buffer: 0x2532f000
  // [INFO] Input size: 27
  p[0] = malloc(19976);
  p[2] = malloc(32776);
}
// The number of actions: 3
// [INFO] Probability: 0.430000
```
