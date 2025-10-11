#include "../include/MeshRatchet.hpp"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

int main() {
    meshratchet::Context ctx;
    auto keys = meshratchet::KeyPair::generate(ctx);
    return 0;
}