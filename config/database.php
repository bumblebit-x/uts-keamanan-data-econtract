<?php
// Otomatis menggunakan SQLite jika MySQL tidak tersedia di device saat ini
$sqlitePath = __DIR__ . '/../database.sqlite';

try {
    $pdo = new PDO("sqlite:" . $sqlitePath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Buat tabel otomatis jika belum ada
    $pdo->exec("CREATE TABLE IF NOT EXISTS system_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_label TEXT NOT NULL,
        public_key_n TEXT NOT NULL,
        public_key_e TEXT NOT NULL,
        symmetric_verifier TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS contracts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nomor_kontrak_cipher TEXT NOT NULL,
        nama_mitra_cipher TEXT NOT NULL,
        nilai_kontrak_cipher TEXT NOT NULL,
        klausul_rahasia_cipher TEXT NOT NULL,
        digital_signature TEXT NOT NULL,
        iv_hex TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    // Seed kunci default jika tabel masih kosong
    $cek = $pdo->query("SELECT COUNT(*) FROM system_keys")->fetchColumn();
    if ($cek == 0) {
        $stmt = $pdo->prepare("INSERT INTO system_keys (admin_label, public_key_n, public_key_e, symmetric_verifier) VALUES (?, ?, ?, ?)");
        $stmt->execute([
            'Administrator Utama (Bembi)',
            '3233',
            '17',
            'a3f8c9e2b1d40765982341abcdef0123456789abcdef0123456789abcdef0123'
        ]);
    }
} catch (PDOException $e) {
    die("Koneksi Database Gagal: " . $e->getMessage());
}
?>