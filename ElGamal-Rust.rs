extern crate num_bigint_dig as num_bigint;
extern crate num_traits;

use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, ToPrimitive};
use primal::is_prime;
use sha2::{Digest, Sha256};

fn generate_prime(bit_length: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    loop {
        let prime_candidate: BigUint = rng.gen_biguint(bit_length);

        if let Some(candidate) = prime_candidate.to_u64() {
            if is_prime(candidate) {
                return prime_candidate;
            }
        }
    }
}

// Функція для знаходження примітивного кореня модуля
fn find_primitive_root(p: &BigUint) -> BigUint {
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let p_minus_one = p - &one;

    let mut g = two.clone();
    while g < p.clone() {
        let mut found = true;
        let mut i = BigUint::one();
        while &i < &p_minus_one {
            let power = &i * &p_minus_one / &two;
            let result = g.modpow(&power, p);
            if result == one {
                found = false;
                break;
            }
            i += 1u32;
        }
        if found {
            return g;
        }
        g += 1u32;
    }
    panic!("No primitive root found");
}

// Функція для генерації ключів
fn generate_keys(p: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let mut rng = rand::thread_rng();
    let p_minus_one = p - BigUint::one();

    // Оберіть випадкове число a (особистий ключ)
    let a = rng.gen_biguint_range(&BigUint::one(), &p_minus_one);

    // Обчисліть відкритий ключ b = g^a mod p
    let b = g.modpow(&a, p);

    (a, b)
}

// Функція для шифрування повідомлення
fn encrypt_message(message: &[u8], p: &BigUint, g: &BigUint, b: &BigUint) -> (BigUint, BigUint) {
    let mut rng = rand::thread_rng();
    let p_minus_one = p - BigUint::one();

    // Оберіть випадкове число k, яке необхідне для шифрування
    let k = rng.gen_biguint_range(&BigUint::one(), &p_minus_one);

    // x = g^k mod p
    let x = g.modpow(&k, p);

    // m – числове представлення повідомлення
    let hashed_message = Sha256::digest(message);
    let hashed_message = BigUint::from_bytes_be(hashed_message.as_slice());

    // y = (b^k * m) mod p
    let y = (b.modpow(&k, p) * &hashed_message) % p;

    (x, y)
}

// Функція для розшифрування повідомлення
fn decrypt_message(x: &BigUint, y: &BigUint, p: &BigUint, a: &BigUint) -> Vec<u8> {
    let p_minus_one = p - BigUint::one();

    // s = x^a mod p
    let s = x.modpow(a, p);

    // m = (y * (s^(-1))) mod p, де s^(-1) – обернене до s в полі за модулем p
    let s_inverse = s.modpow(&p_minus_one, p);
    let m = (y * &s_inverse) % p;

    // Повернути розшифроване повідомлення у вигляді байтового масиву
    let m_bytes = m.to_bytes_be();
    m_bytes
}

fn verify_signature(
    signature: &(BigUint, BigUint),
    p: &BigUint,
    g: &BigUint,
    a: &BigUint,
    message_hash: &BigUint,
) -> bool {
    let (x, y) = signature;

    let p_minus_one = p - BigUint::one();

    // w = s^(-1) mod p
    let s = x.modpow(a, p);
    let s_inverse = s.modpow(&p_minus_one, p);

    // u1 = (H(m) * w) mod p
    let u1 = (message_hash * &s_inverse) % p;

    // u2 = (r * w) mod p
    let u2 = (y * &s_inverse) % p;

    // v = ((g^u1 * y^u2) mod p) mod q
    let v = ((g.modpow(&u1, p) * y.modpow(&u2, p)) % p) % &p_minus_one;

    // Перевірка, чи співпадає v з x
    v == *x
}

fn main() {
    for x in 2048..=4096 {
        let p = generate_prime(x);
        let g = find_primitive_root(&p);

        let (a, b) = generate_keys(&p, &g);

        let message = b"Hello, world!";
        let (x, y) = encrypt_message(message, &p, &g, &b);

        let decrypted_message = decrypt_message(&x, &y, &p, &a);

        println!("Зашифроване повідомлення: {:?}", (x.clone(), y.clone()));
        println!("Розшифроване повідомлення: {:?}", decrypted_message);

        if decrypted_message == message {
            println!("Шифрування та розшифрування пройшли успішно");
        } else {
            println!("Помилка у шифруванні або розшифруванні");
        }

        // Перевірка коректності підпису
        let message_hash = Sha256::digest(message);
        let message_hash = BigUint::from_bytes_be(message_hash.as_slice());

        let signature = (x.clone(), y.clone());
        let verified = verify_signature(&signature, &p, &g, &a, &message_hash);
        println!("Перевірка підпису: {}", verified);

        // Перевірка з пошкодженими даними
        let corrupted_y = y + BigUint::one();
        let corrupted_signature = (x.clone(), corrupted_y);
        let corrupted_verified = verify_signature(&corrupted_signature, &p, &g, &a, &message_hash);
        println!("Перевірка з пошкодженими даними: {}", corrupted_verified);

        println!("---");
    }
}
