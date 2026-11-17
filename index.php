<?php
session_start();
require_once 'config/database.php';
require_once 'core/crypto.php';

if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    header("Location: admin.php");
    exit;
}

$error = '';
$success = '';
$generatedKeys = null;

// Pastikan verifier default sesuai dengan kunci default "UMMI-INFORMATIKA-2026"
$stmtInit = $pdo->query("SELECT * FROM system_keys ORDER BY id DESC LIMIT 1");
$activeKeyConfig = $stmtInit->fetch(PDO::FETCH_ASSOC);

if ($activeKeyConfig && $activeKeyConfig['symmetric_verifier'] === 'a3f8c9e2b1d40765982341abcdef0123456789abcdef0123456789abcdef0123') {
    $realDefaultHash = HybridCrypto::hashSymmetricVerifier('UMMI-INFORMATIKA-2026');
    $upd = $pdo->prepare("UPDATE system_keys SET symmetric_verifier = ? WHERE id = ?");
    $upd->execute([$realDefaultHash, $activeKeyConfig['id']]);
    $activeKeyConfig['symmetric_verifier'] = $realDefaultHash;
}

// Proses Generate & Terapkan Kunci Baru
if (isset($_POST['generate_new_keys'])) {
    $newSymKey = trim($_POST['new_symmetric_key']);
    $adminLabel = trim($_POST['admin_label']) ?: 'Administrator Legal & Kontrak';

    if (strlen($newSymKey) < 6) {
        $error = "Kunci simetris minimal harus terdiri dari 6 karakter.";
    } else {
        $rsa = HybridCrypto::generateRSAKeyPair();
        $symHash = HybridCrypto::hashSymmetricVerifier($newSymKey);

        $pdo->exec("DELETE FROM contracts");
        $pdo->exec("DELETE FROM system_keys");

        $stmt = $pdo->prepare("INSERT INTO system_keys (admin_label, public_key_n, public_key_e, symmetric_verifier) VALUES (?, ?, ?, ?)");
        $stmt->execute([$adminLabel, $rsa['n'], $rsa['e'], $symHash]);

        $generatedKeys = [
            'symmetric'   => $newSymKey,
            'private_key' => $rsa['private_key'],
            'public_key'  => $rsa['public_key']
        ];
        $success = "Otoritas kunci kriptografi baru berhasil dikonfigurasi.";

        $stmtInit = $pdo->query("SELECT * FROM system_keys ORDER BY id DESC LIMIT 1");
        $activeKeyConfig = $stmtInit->fetch(PDO::FETCH_ASSOC);
    }
}

// Proses Login dengan Paradigma Kunci Simetris + Asimetris
if (isset($_POST['login_vault'])) {
    $inputSymKey = trim($_POST['symmetric_key']);
    $inputAsymKey = trim($_POST['asymmetric_key']);

    if (empty($inputSymKey) || empty($inputAsymKey)) {
        $error = "Kunci Simetris dan Kunci Asimetris (Private Key) wajib diisi untuk otentikasi.";
    } else {
        $inputSymHash = HybridCrypto::hashSymmetricVerifier($inputSymKey);
        $isSymValid = hash_equals($activeKeyConfig['symmetric_verifier'], $inputSymHash);
        $isAsymValid = HybridCrypto::verifyAsymmetricKey(
            $inputAsymKey,
            $activeKeyConfig['public_key_e'],
            $activeKeyConfig['public_key_n']
        );

        if ($isSymValid && $isAsymValid) {
            $_SESSION['authenticated'] = true;
            $_SESSION['admin_label'] = $activeKeyConfig['admin_label'];
            $_SESSION['symmetric_key'] = $inputSymKey;
            $_SESSION['asymmetric_key'] = $inputAsymKey;
            $_SESSION['public_key'] = $activeKeyConfig['public_key_e'] . ':' . $activeKeyConfig['public_key_n'];
            header("Location: admin.php");
            exit;
        } else {
            if (!$isSymValid && !$isAsymValid) {
                $error = "Akses Ditolak: Kunci Simetris dan Kunci Asimetris tidak valid.";
            } elseif (!$isSymValid) {
                $error = "Akses Ditolak: Kunci Simetris (AES Passphrase) tidak sesuai.";
            } else {
                $error = "Akses Ditolak: Kunci Asimetris (Private Key RSA) gagal diverifikasi oleh Public Key.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E-Contract Repository | Sistem Pengarsipan Kontrak Kerja</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f8fafc;
            background-image: radial-gradient(#cbd5e1 0.75px, transparent 0.75px);
            background-size: 24px 24px;
        }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
    </style>
</head>
<body class="text-slate-800 min-h-screen flex flex-col justify-between antialiased">

    <!-- Corporate Top Navigation -->
    <header class="bg-white/95 backdrop-blur border-b border-slate-200 sticky top-0 z-30">
        <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3.5">
                <div class="w-9 h-9 rounded-lg bg-blue-700 text-white flex items-center justify-center shadow-sm">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                    </svg>
                </div>
                <div class="border-l border-slate-200 pl-3.5">
                    <span class="font-bold text-slate-900 tracking-tight text-base block leading-none">E-CONTRACT REPOSITORY</span>
                    <span class="text-[11px] text-slate-500 font-medium tracking-wide uppercase mt-1 block">Enterprise Legal & Agreement Archive</span>
                </div>
            </div>

            <div class="flex items-center gap-3">
                <span class="hidden sm:inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 bg-slate-100 px-3 py-1.5 rounded-md border border-slate-200">
                    <span class="w-1.5 h-1.5 rounded-full bg-blue-600"></span>
                    Hybrid Cryptography Protocol
                </span>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="max-w-6xl mx-auto w-full px-6 py-12">
        <div class="grid lg:grid-cols-12 gap-12 items-center">

            <!-- Left Column: Institutional Overview & Key Registry -->
            <div class="lg:col-span-6 space-y-6">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-blue-50 border border-blue-200 text-blue-800 text-xs font-semibold tracking-wide uppercase">
                    Keamanan Data & Informasi &bull; Otorisasi Dokumen
                </div>

                <h1 class="text-3xl sm:text-4xl font-bold text-slate-900 tracking-tight leading-[1.2]">
                    Sistem Pengarsipan Surat Perjanjian & Kontrak Kerja Terenkripsi.
                </h1>

                <p class="text-slate-600 text-sm sm:text-base leading-relaxed">
                    Seluruh dokumen perjanjian dan klausul kerja sama dilindungi dengan enkripsi tingkat lanjut. Akses ke ruang kendali administrator memerlukan validasi <strong>Kunci Simetris</strong> dan <strong>Kunci Asimetris Privat</strong> secara bersamaan.
                </p>

                <!-- Server Public Key Card -->
                <div class="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                    <div class="px-5 py-3 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                        <span class="text-xs font-semibold text-slate-700 uppercase tracking-wider">Registri Public Key Server (RSA)</span>
                        <span class="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                            Aktif
                        </span>
                    </div>
                    <div class="p-5 space-y-3">
                        <div class="flex items-center justify-between bg-slate-900 text-slate-100 px-4 py-2.5 rounded-lg font-mono text-xs">
                            <span class="text-slate-400">RSA Public Key (e:n)</span>
                            <span class="text-blue-300 font-semibold"><?= htmlspecialchars($activeKeyConfig['public_key_e'] . ':' . $activeKeyConfig['public_key_n']) ?></span>
                        </div>
                        <div class="pt-1 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-500">
                            <div>
                                <span class="font-medium text-slate-700">Kredensial Uji Coba:</span>
                                <span class="font-mono text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded ml-1">UMMI-INFORMATIKA-2026</span>
                            </div>
                            <div>
                                <span class="font-medium text-slate-700">Private:</span>
                                <span class="font-mono text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded ml-1">2753:3233</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Collapsible Key Generator (Biar Ringkas & Rapi) -->
                <details class="group bg-white rounded-xl border border-slate-200 shadow-sm" <?= $generatedKeys ? 'open' : '' ?>>
                    <summary class="px-5 py-3.5 cursor-pointer list-none flex items-center justify-between text-xs font-semibold text-slate-700 hover:text-blue-700 transition">
                        <span class="flex items-center gap-2">
                            <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
                            Konfigurasi / Generate Pasangan Kunci Baru (Opsional)
                        </span>
                        <span class="text-slate-400 group-open:rotate-180 transition-transform">&#9662;</span>
                    </summary>
                    <div class="px-5 pb-5 pt-2 border-t border-slate-100 space-y-3">
                        <p class="text-xs text-slate-500">Membuat Kunci Simetris & Pasangan Kunci RSA baru akan me-reset arsip kontrak sebelumnya agar sesuai dengan kunci baru.</p>
                        <form method="POST" class="flex flex-col sm:flex-row gap-2">
                            <input type="hidden" name="admin_label" value="Administrator Legal">
                            <input type="text" name="new_symmetric_key" placeholder="Masukkan Kunci Simetris Baru..." required
                                class="flex-1 text-xs font-mono px-3 py-2 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-600">
                            <button type="submit" name="generate_new_keys"
                                class="bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold px-4 py-2 rounded-lg transition whitespace-nowrap">
                                Generate Kunci
                            </button>
                        </form>

                        <?php if ($generatedKeys): ?>
                            <div class="p-3 bg-blue-50/70 rounded-lg border border-blue-200 text-xs font-mono space-y-1 text-slate-700">
                                <div class="text-blue-900 font-semibold font-sans mb-1">Salin Kunci Baru Berikut untuk Login:</div>
                                <div>Kunci Simetris : <span class="text-blue-700 font-semibold select-all"><?= htmlspecialchars($generatedKeys['symmetric']) ?></span></div>
                                <div>Private Key RSA: <span class="text-blue-700 font-semibold select-all"><?= htmlspecialchars($generatedKeys['private_key']) ?></span></div>
                                <div>Public Key RSA : <span class="text-slate-500"><?= htmlspecialchars($generatedKeys['public_key']) ?></span></div>
                            </div>
                        <?php endif; ?>
                    </div>
                </details>
            </div>

            <!-- Right Column: Formal Authentication Card -->
            <div class="lg:col-span-6">
                <div class="bg-white rounded-xl border border-slate-200 shadow-md overflow-hidden">
                    <div class="px-8 py-6 bg-slate-900 text-white">
                        <h2 class="text-lg font-semibold tracking-tight">Otentikasi Akses Administrator</h2>
                        <p class="text-xs text-slate-400 mt-1">Masukkan kredensial kunci kriptografi untuk membuka sesi dekripsi repositori.</p>
                    </div>

                    <div class="p-8">
                        <?php if ($error): ?>
                            <div class="mb-6 p-3.5 rounded-lg bg-red-50 border-l-4 border-red-600 text-red-800 text-xs font-medium">
                                <?= htmlspecialchars($error) ?>
                            </div>
                        <?php endif; ?>

                        <?php if ($success): ?>
                            <div class="mb-6 p-3.5 rounded-lg bg-emerald-50 border-l-4 border-emerald-600 text-emerald-800 text-xs font-medium">
                                <?= htmlspecialchars($success) ?>
                            </div>
                        <?php endif; ?>

                        <form method="POST" class="space-y-5">
                            <div>
                                <div class="flex items-center justify-between mb-1.5">
                                    <label class="text-xs font-semibold uppercase tracking-wider text-slate-700">
                                        Kunci Simetris (AES-256)
                                    </label>
                                    <span class="text-[11px] text-slate-400 font-mono">Symmetric Key</span>
                                </div>
                                <input type="password" name="symmetric_key" placeholder="Masukkan Secret Key Simetris" required
                                    class="w-full font-mono text-sm px-3.5 py-2.5 rounded-lg border border-slate-300 bg-slate-50/50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-700 focus:border-blue-700 transition">
                            </div>

                            <div>
                                <div class="flex items-center justify-between mb-1.5">
                                    <label class="text-xs font-semibold uppercase tracking-wider text-slate-700">
                                        Kunci Asimetris (RSA Private Key)
                                    </label>
                                    <span class="text-[11px] text-slate-400 font-mono">Format d:n</span>
                                </div>
                                <textarea name="asymmetric_key" rows="3" placeholder="Masukkan Private Key Asimetris (contoh: 2753:3233)" required
                                    class="w-full font-mono text-sm px-3.5 py-2.5 rounded-lg border border-slate-300 bg-slate-50/50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-700 focus:border-blue-700 transition"></textarea>
                            </div>

                            <div class="pt-2">
                                <button type="submit" name="login_vault"
                                    class="w-full bg-blue-700 hover:bg-blue-800 text-white text-sm font-semibold py-3 px-5 rounded-lg shadow-sm transition flex items-center justify-center gap-2">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                    </svg>
                                    Verifikasi Kunci & Masuk ke Sistem
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

        </div>
    </main>

    <!-- Corporate Footer -->
    <footer class="bg-white border-t border-slate-200 py-4">
        <div class="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-500">
            <span>&copy; 2026 E-Contract Repository System. Hak Cipta Dilindungi.</span>
            <span class="font-mono text-[11px] text-slate-400">AES-256-CBC &bull; RSA Asymmetric Signature</span>
        </div>
    </footer>

</body>
</html>