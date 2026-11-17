<?php

class HybridCrypto {
    // 1. Pembangkit Pasangan Kunci Asimetris (RSA)
    public static function generateRSAKeyPair() {
        // Menggunakan bilangan prima 16-bit/32-bit yang aman untuk PHP integer 64-bit
        $primes = [
            1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061,
            1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123,
            1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213
        ];
        
        $p = $primes[array_rand($primes)];
        do {
            $q = $primes[array_rand($primes)];
        } while ($p === $q);

        $n = $p * $q;
        $phi = ($p - 1) * ($q - 1);

        // Pilih e yang koprima dengan phi
        $e = 17;
        while (self::gcd($e, $phi) !== 1) {
            $e += 2;
        }

        // Hitung modular inverse d
        $d = self::modInverse($e, $phi);

        return [
            'public_key'  => $e . ':' . $n,
            'private_key' => $d . ':' . $n,
            'e' => (string)$e,
            'd' => (string)$d,
            'n' => (string)$n
        ];
    }

    private static function gcd($a, $b) {
        while ($b != 0) {
            $t = $b;
            $b = $a % $b;
            $a = $t;
        }
        return $a;
    }

    private static function modInverse($a, $m) {
        $m0 = $m;
        $y = 0;
        $x = 1;
        if ($m == 1) return 0;
        while ($a > 1) {
            $q = intdiv($a, $m);
            $t = $m;
            $m = $a % $m;
            $a = $t;
            $t = $y;
            $y = $x - $q * $y;
            $x = $t;
        }
        if ($x < 0) $x += $m0;
        return $x;
    }

    // Modular Exponentiation: (base^exp) % mod
    public static function modPow($base, $exp, $mod) {
        $result = 1;
        $base = $base % $mod;
        while ($exp > 0) {
            if ($exp % 2 == 1) {
                $result = ($result * $base) % $mod;
            }
            $exp = $exp >> 1;
            $base = ($base * $base) % $mod;
        }
        return $result;
    }

    // 2. Verifikasi Kunci Asimetris (Challenge-Response RSA)
    // Mengenkripsi tantangan dengan Public Key (e, n) lalu mendekripsinya dengan Private Key inputan user (d, n)
    public static function verifyAsymmetricKey($privateKeyStr, $publicKeyE, $publicKeyN) {
        $parts = explode(':', trim($privateKeyStr));
        if (count($parts) !== 2) return false;

        $d = (int)$parts[0];
        $n = (int)$parts[1];
        $e = (int)$publicKeyE;
        $storedN = (int)$publicKeyN;

        if ($n !== $storedN || $d <= 1) return false;

        // Uji kriptografi matematis: M = 420 -> C = M^e mod n -> M' = C^d mod n
        $challenge = 420;
        $cipherChallenge = self::modPow($challenge, $e, $storedN);
        $decryptedChallenge = self::modPow($cipherChallenge, $d, $n);

        return $decryptedChallenge === $challenge;
    }

    // 3. Membuat Digital Signature Asimetris untuk setiap dokumen kontrak
    public static function signData($dataString, $privateKeyStr) {
        $parts = explode(':', trim($privateKeyStr));
        if (count($parts) !== 2) return 'INVALID_SIG';
        $d = (int)$parts[0];
        $n = (int)$parts[1];

        // Ambil hash CRC32 positif sebagai representasi ringkas dokumen
        $hashInt = abs(crc32($dataString)) % ($n - 1);
        if ($hashInt === 0) $hashInt = 7;
        $signature = self::modPow($hashInt, $d, $n);
        return strtoupper(dechex($signature)) . '-RSA-' . $n;
    }

    // 4. Enkripsi Simetris (AES-256-CBC)
    public static function encryptSymmetric($plaintext, $symmetricKey, $ivHex) {
        $key = hash('sha256', $symmetricKey, true);
        $iv = hex2bin($ivHex);
        $ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($ciphertext);
    }

    // 5. Dekripsi Simetris (AES-256-CBC)
    public static function decryptSymmetric($ciphertextBase64, $symmetricKey, $ivHex) {
        $key = hash('sha256', $symmetricKey, true);
        $iv = hex2bin($ivHex);
        $decrypted = openssl_decrypt(base64_decode($ciphertextBase64), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return $decrypted !== false ? $decrypted : '[Gagal Dekripsi - Kunci Salah]';
    }

    // Generate IV Acak 16-byte (32 karakter hex)
    public static function generateIV() {
        return bin2hex(random_bytes(16));
    }

    // Hash Verifier untuk Kunci Simetris
    public static function hashSymmetricVerifier($symmetricKey) {
        return hash('sha256', 'ECONTRACT_SALT_' . trim($symmetricKey));
    }
}
?>