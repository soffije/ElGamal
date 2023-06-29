# ElGamal

Here's a description of each function in the provided code:

1. `generate_prime(bit_length: usize) -> BigUint`: This function generates a prime number of the specified bit length using a random number generator (`rng`). It generates a random number as a candidate for a prime and checks if it is prime using the `is_prime` function from the `primal` crate. It repeats this process until a prime number is found and returns it as a `BigUint`.

2. `find_primitive_root(p: &BigUint) -> BigUint`: This function finds a primitive root modulo `p` by iterating over possible values of `g` starting from 2. For each value of `g`, it checks if it satisfies the condition for being a primitive root by performing modular exponentiation with powers of `g` and verifying that none of the results are equal to 1. If a primitive root is found, it is returned as a `BigUint`. If no primitive root is found, it panics with an error message.

3. `generate_keys(p: &BigUint, g: &BigUint) -> (BigUint, BigUint)`: This function generates a pair of keys `(a, b)` for encryption. It generates a random private key `a` by selecting a random number between 1 and `p - 1` using the `gen_biguint_range` method from the random number generator (`rng`). The public key `b` is then calculated as `g` raised to the power of `a` modulo `p`. The function returns the generated keys as a tuple `(a, b)`.

4. `encrypt_message(message: &[u8], p: &BigUint, g: &BigUint, b: &BigUint) -> (BigUint, BigUint)`: This function encrypts a message using the provided parameters. It first generates a random value `k` between 1 and `p - 1` using the random number generator (`rng`). It then calculates `x` as `g` raised to the power of `k` modulo `p`. The message is hashed using the SHA-256 algorithm, and the resulting hash is converted to a `BigUint` called `hashed_message`. Finally, the encrypted value `y` is calculated as `(b` raised to the power of `k` modulo `p`) multiplied by `hashed_message` modulo `p`. The function returns the pair `(x, y)`.

5. `decrypt_message(x: &BigUint, y: &BigUint, p: &BigUint, a: &BigUint) -> Vec<u8>`: This function decrypts a message given the encrypted values `x` and `y`, the prime modulus `p`, and the private key `a`. It first calculates `s` as `x` raised to the power of `a` modulo `p`. Then, it calculates the inverse of `s` modulo `p` as `s_inverse`. The decrypted message `m` is obtained by multiplying `y` by `s_inverse` modulo `p`. The function returns the decrypted message as a `Vec<u8>`.

6. `verify_signature(signature: &(BigUint, BigUint), p: &BigUint, g: &BigUint, a: &BigUint, message_hash: &BigUint) -> bool`: This function verifies the correctness of a signature given the signature `(x, y)`, the prime modulus `p`, the primitive root `g`, the private key `a`, and the hash of the original message `message_hash`. It calculates `s` as `x` raised to the power of `a` modulo `p` and then calculates the inverse of `s`

 modulo `p` as `s_inverse`. It computes `u1` as the product of `message_hash` and `s_inverse` modulo `p`, and `u2` as the product of `y` and `s_inverse` modulo `p`. Finally, it computes `v` as the result of a series of modular exponentiations involving `g`, `u1`, `y`, and `u2`. The function returns `true` if `v` is equal to `x`, indicating that the signature is valid, and `false` otherwise.

The `main` function demonstrates the usage of these functions by generating keys, encrypting and decrypting a message, and verifying the signature. It iterates over a range of bit lengths for generating prime numbers, performs the operations for each bit length, and outputs the results.
