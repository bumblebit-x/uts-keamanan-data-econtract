CREATE DATABASE IF NOT EXISTS db_econtract_vault;
USE db_econtract_vault;

-- Tabel konfigurasi otoritas kunci (menyimpan Public Key & Challenge Token)
CREATE TABLE IF NOT EXISTS system_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_label VARCHAR(100) NOT NULL,
    public_key_n TEXT NOT NULL,
    public_key_e VARCHAR(50) NOT NULL,
    symmetric_verifier TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabel arsip kontrak (seluruh kolom data menyimpan hasil enkripsi / ciphertext)
CREATE TABLE IF NOT EXISTS contracts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nomor_kontrak_cipher TEXT NOT NULL,
    nama_mitra_cipher TEXT NOT NULL,
    nilai_kontrak_cipher TEXT NOT NULL,
    klausul_rahasia_cipher TEXT NOT NULL,
    digital_signature TEXT NOT NULL,
    iv_hex VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Data Kunci Default untuk Demo / Login Awal
-- Kunci Simetris Default  : UMMI-INFORMATIKA-2026
-- Kunci Asimetris Default : 2753:3233 (Format Private Key d:n)
INSERT INTO system_keys (admin_label, public_key_n, public_key_e, symmetric_verifier) VALUES (
    'Administrator Utama (Bembi)',
    '3233',
    '17',
    'a3f8c9e2b1d40765982341abcdef0123456789abcdef0123456789abcdef0123'
);