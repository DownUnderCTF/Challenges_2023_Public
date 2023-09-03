// g++ collisions.cpp -o collisions

#include <climits>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <unordered_map>

#define MAX_ATOMS    32
#define BUCKET_COUNT 59

typedef std::unordered_map<unsigned int, uint64_t> atoms_t;

unsigned int random_value() {
    return rand() % UINT_MAX;
}

int main() {
    srand(time(0));

    atoms_t atoms;
    atoms_t::hasher hash_fn = atoms.hash_function();

    unsigned int collisions[MAX_ATOMS - 1];
    size_t target = hash_fn(0x13371337);

    size_t found = 0;
    while (found < MAX_ATOMS - 1) {
        unsigned int value = random_value();
        size_t hash = hash_fn(value);

        if (target % 1 == hash % 1 &&
                target % 13 == hash % 13 &&
                target % 29 == hash % 29 &&
                target % 59 == hash % 59) {
            collisions[found++] = value;
        }
    }

    for (size_t i = 0; i < MAX_ATOMS - 1; i++) {
        std::cout << "0x" << std::hex << collisions[i]
                  << std::endl;
    }

    return 0;
}

