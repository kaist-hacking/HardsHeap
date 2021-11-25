#include <stdio.h>
#include "api.h"

WEAK_ATTRIBUTE void initialize() {}

WEAK_ATTRIBUTE void finalize() {}

WEAK_ATTRIBUTE void analyze_single() {}

WEAK_ATTRIBUTE double calculate_prob() { return 0; }
