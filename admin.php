<?php
session_start();
require_once 'config/database.php';
require_once 'core/crypto.php';

if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    header("Location: index.php");
    exit;
}

$symKey = $_SESSION['symmetric_key'];
$asymKey = $_SESSION['asymmetric_key'];
$notif = '';

// Proses Simpan Kontrak Baru (Langsung Enkripsi sebelum masuk Database)
if (isset($_POST['simpan_kontrak'])) {
    $noKontrak = trim($_POST['nomor_kontrak']);
    $mitra = trim($_POST['nama_mitra']);
    $nilai = trim($_POST['nilai_kontrak']);
    $klausul = trim($_POST['klausul_rahasia']);

    if ($noKontrak && $mitra && $nilai && $klausul) {
        $ivHex = HybridCrypto::generateIV();

        $cipherNo = HybridCrypto::encryptSymmetric($noKontrak, $symKey, $ivHex);
        $cipherMitra = HybridCrypto::encryptSymmetric($mitra, $symKey, $ivHex);
        $cipherNilai = HybridCrypto::encryptSymmetric($nilai, $symKey, $ivHex);
        $cipherKlausul = HybridCrypto::encryptSymmetric($klausul, $symKey, $ivHex);

        $rawBundle = $noKontrak . '|' . $mitra . '|' . $nilai . '|' . $klausul;
        $signature = HybridCrypto::signData($rawBundle, $asymKey);

        $stmt = $pdo->prepare("INSERT INTO contracts (nomor_kontrak_cipher, nama_mitra_cipher, nilai_kontrak_cipher, klausul_rahasia_cipher, digital_signature, iv_hex) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([$cipherNo, $cipherMitra, $cipherNilai, $cipherKlausul, $signature, $ivHex]);

        $notif = "Dokumen kontrak berhasil dienkripsi dengan AES-256-CBC dan ditandatangani secara digital (RSA) sebelum disimpan ke repositori.";
    }
}

// Hapus Kontrak
if (isset($_GET['hapus'])) {
    $id = (int)$_GET['hapus'];
    $stmt = $pdo->prepare("DELETE FROM contracts WHERE id = ?");
    $stmt->execute([$id]);
    header("Location: admin.php");
    exit;
}

$contracts = $pdo->query("SELECT * FROM contracts ORDER BY id DESC")->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Workspace | E-Contract Repository</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f8fafc; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
    </style>
</head>
<body class="text-slate-800 min-h-screen antialiased">

    <!-- Enterprise Header -->
    <header class="bg-white border-b border-slate-200 sticky top-0 z-30">
        <div class="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-4">
            <div class="flex items-center gap-3.5">
                <div class="w-9 h-9 rounded-lg bg-blue-700 text-white flex items-center justify-center shadow-sm">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                    </svg>
                </div>
                <div class="border-l border-slate-200 pl-3.5">
                    <span class="font-bold text-slate-900 tracking-tight text-sm sm:text-base block leading-none">E-CONTRACT REPOSITORY</span>
                    <span class="text-[11px] text-slate-500 mt-1 block">Workspace Administrator &bull; <?= htmlspecialchars($_SESSION['admin_label']) ?></span>
                </div>
            </div>

            <div class="flex items-center gap-3">
                <span class="hidden md:inline-block text-xs font-mono text-slate-600 bg-slate-100 px-3 py-1.5 rounded-md border border-slate-200">
                    Public Key: <?= htmlspecialchars($_SESSION['public_key']) ?>
                </span>
                <a href="logout.php" class="bg-slate-900 hover:bg-red-700 text-white text-xs font-semibold px-4 py-2 rounded-lg transition">
                    Akhiri Sesi & Kunci
                </a>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-8 space-y-8">

        <!-- Status Bar -->
        <div class="grid sm:grid-cols-3 gap-4">
            <div class="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
                <div>
                    <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Total Arsip Terenkripsi</span>
                    <p class="text-2xl font-bold text-slate-900 mt-0.5"><?= count($contracts) ?> <span class="text-xs font-normal text-slate-500">Dokumen</span></p>
                </div>
                <div class="w-10 h-10 rounded-lg bg-blue-50 text-blue-700 flex items-center justify-center font-bold text-sm">DB</div>
            </div>
            <div class="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
                <div>
                    <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Enkripsi Penyimpanan</span>
                    <p class="text-sm font-bold text-slate-900 mt-1 font-mono">AES-256-CBC (128-bit IV)</p>
                </div>
                <div class="w-10 h-10 rounded-lg bg-emerald-50 text-emerald-700 flex items-center justify-center font-bold text-xs">SYM</div>
            </div>
            <div class="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
                <div>
                    <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Integritas & Tanda Tangan</span>
                    <p class="text-sm font-bold text-slate-900 mt-1 font-mono">RSA Digital Signature</p>
                </div>
                <div class="w-10 h-10 rounded-lg bg-indigo-50 text-indigo-700 flex items-center justify-center font-bold text-xs">ASYM</div>
            </div>
        </div>

        <?php if ($notif): ?>
            <div class="p-4 rounded-xl bg-emerald-50 border-l-4 border-emerald-600 text-emerald-900 text-xs sm:text-sm font-medium shadow-sm">
                <?= htmlspecialchars($notif) ?>
            </div>
        <?php endif; ?>

        <!-- Form Input Surat Perjanjian / Kontrak -->
        <section class="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div class="px-6 py-4 bg-slate-50 border-b border-slate-200">
                <h2 class="text-sm font-bold uppercase tracking-wider text-slate-800">Registrasi Surat Perjanjian / Kontrak Kerja Baru</h2>
                <p class="text-xs text-slate-500 mt-0.5">Input data plaintext di bawah ini. Sistem akan mengenkripsi seluruh atribut sebelum ditulis ke database.</p>
            </div>

            <form method="POST" class="p-6 grid md:grid-cols-3 gap-5">
                <div>
                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Nomor Surat Perjanjian / Kontrak</label>
                    <input type="text" name="nomor_kontrak" placeholder="Contoh: SPK/LGL/2026/XI/014" required
                        class="w-full text-sm px-3.5 py-2.5 rounded-lg border border-slate-300 bg-slate-50/50 focus:bg-white focus:ring-2 focus:ring-blue-700 focus:outline-none">
                </div>

                <div>
                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Nama Mitra / Pihak Kedua</label>
                    <input type="text" name="nama_mitra" placeholder="Contoh: PT Cakrawala Solusi Digital" required
                        class="w-full text-sm px-3.5 py-2.5 rounded-lg border border-slate-300 bg-slate-50/50 focus:bg-white focus:ring-2 focus:ring-blue-700 focus:outline-none">
                </div>

                <div>
                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Nilai Kontrak Kerja Sama</label>
                    <input type="text" name="nilai_kontrak" placeholder="Contoh: Rp 750.000.000,-" required
                        class="w-full text-sm px-3.5 py-2.5 rounded-lg border border-slate-300 bg-slate-50/50 focus:bg-white focus:ring-2 focus:ring-blue-700 focus:outline-none">
                </div>

                <div class="md:col-span-3">
                    <label class="block text-xs font-semibold text-slate-700 mb-1.5">Klausul Rahasia & Lingkup Perjanjian</label>
                    <textarea name="klausul_rahasia" rows="2" placeholder="Tuliskan ruang lingkup pekerjaan, ketentuan kerahasiaan (NDA), atau klausul khusus..." required
                        class="w-full text-sm px-3.5 py-2.5 rounded-lg border border-slate-300 bg-slate-50/50 focus:bg-white focus:ring-2 focus:ring-blue-700 focus:outline-none"></textarea>
                </div>

                <div class="md:col-span-3 flex justify-end pt-1">
                    <button type="submit" name="simpan_kontrak"
                        class="bg-blue-700 hover:bg-blue-800 text-white text-xs sm:text-sm font-semibold px-6 py-2.5 rounded-lg shadow-sm transition">
                        Enkripsi & Arsipkan Kontrak
                    </button>
                </div>
            </form>
        </section>

        <!-- Tabel Konten Hasil Enkripsi (Ciphertext) -->
        <section class="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div class="px-6 py-4 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-4">
                <div>
                    <h2 class="text-sm font-bold uppercase tracking-wider text-slate-800">Daftar Arsip Kontrak Tersimpan (Ciphertext Database View)</h2>
                    <p class="text-xs text-slate-500 mt-0.5">Menampilkan seluruh konten hasil enkripsi sebagaimana tersimpan di dalam basis data.</p>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-900 text-slate-200 text-[11px] uppercase tracking-wider">
                            <th class="py-3.5 px-4">No</th>
                            <th class="py-3.5 px-4">No. Kontrak (Ciphertext)</th>
                            <th class="py-3.5 px-4">Nama Mitra (Ciphertext)</th>
                            <th class="py-3.5 px-4">Nilai Kontrak (Ciphertext)</th>
                            <th class="py-3.5 px-4">Klausul Rahasia (Ciphertext)</th>
                            <th class="py-3.5 px-4">Digital Signature & IV</th>
                            <th class="py-3.5 px-4 text-center">Opsi</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200 text-xs font-mono">
                        <?php if (empty($contracts)): ?>
                            <tr>
                                <td colspan="7" class="py-12 text-center text-slate-400 font-sans text-sm">
                                    Repositori masih kosong. Silakan tambahkan dokumen kontrak melalui formulir di atas.
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($contracts as $idx => $row):
                                $decNo = HybridCrypto::decryptSymmetric($row['nomor_kontrak_cipher'], $symKey, $row['iv_hex']);
                                $decMitra = HybridCrypto::decryptSymmetric($row['nama_mitra_cipher'], $symKey, $row['iv_hex']);
                                $decNilai = HybridCrypto::decryptSymmetric($row['nilai_kontrak_cipher'], $symKey, $row['iv_hex']);
                                $decKlausul = HybridCrypto::decryptSymmetric($row['klausul_rahasia_cipher'], $symKey, $row['iv_hex']);
                            ?>
                            <tr class="hover:bg-slate-50 align-top">
                                <td class="py-4 px-4 font-bold text-slate-700"><?= $idx + 1 ?></td>
                                <td class="py-4 px-4 max-w-[160px] break-all text-blue-800 bg-blue-50/30">
                                    <?= htmlspecialchars($row['nomor_kontrak_cipher']) ?>
                                </td>
                                <td class="py-4 px-4 max-w-[180px] break-all text-slate-700">
                                    <?= htmlspecialchars($row['nama_mitra_cipher']) ?>
                                </td>
                                <td class="py-4 px-4 max-w-[160px] break-all text-slate-700">
                                    <?= htmlspecialchars($row['nilai_kontrak_cipher']) ?>
                                </td>
                                <td class="py-4 px-4 max-w-[240px] break-all text-slate-600">
                                    <?= htmlspecialchars($row['klausul_rahasia_cipher']) ?>
                                </td>
                                <td class="py-4 px-4 max-w-[175px] break-all text-emerald-700">
                                    <span class="block font-semibold">SIG: <?= htmlspecialchars($row['digital_signature']) ?></span>
                                    <span class="block text-[10px] text-slate-400 mt-1">IV: <?= htmlspecialchars($row['iv_hex']) ?></span>
                                </td>
                                <td class="py-4 px-4 text-center font-sans space-y-1.5">
                                    <button type="button"
                                        onclick='bukaModalDekripsi(<?= json_encode([
                                            "no" => $decNo,
                                            "mitra" => $decMitra,
                                            "nilai" => $decNilai,
                                            "klausul" => $decKlausul,
                                            "sig" => $row["digital_signature"]
                                        ]) ?>)'
                                        class="w-full bg-blue-700 hover:bg-blue-800 text-white text-xs font-medium px-3 py-1.5 rounded-md transition">
                                        Dekripsi
                                    </button>
                                    <a href="?hapus=<?= $row['id'] ?>" onclick="return confirm('Hapus dokumen kontrak terenkripsi ini?')"
                                        class="block w-full bg-white border border-slate-300 hover:bg-red-50 hover:border-red-300 text-slate-600 hover:text-red-700 text-xs font-medium px-3 py-1.5 rounded-md transition">
                                        Hapus
                                    </a>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>
    </main>

    <!-- Modal Hasil Dekripsi Plaintext -->
    <div id="modalDekripsi" class="fixed inset-0 bg-slate-900/60 backdrop-blur-xs hidden items-center justify-center p-4 z-50">
        <div class="bg-white rounded-xl border border-slate-200 max-w-lg w-full overflow-hidden shadow-2xl">
            <div class="px-6 py-4 bg-slate-900 text-white flex items-center justify-between">
                <h3 class="font-semibold text-sm tracking-wide uppercase">Hasil Dekripsi Dokumen Kontrak (Plaintext)</h3>
                <button onclick="tutupModal()" class="text-slate-400 hover:text-white text-xl leading-none">&times;</button>
            </div>
            <div class="p-6 space-y-4 text-sm">
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <span class="text-[11px] uppercase tracking-wider text-slate-400 font-semibold block">Nomor Kontrak</span>
                        <p id="mNo" class="font-semibold text-slate-900 mt-0.5"></p>
                    </div>
                    <div>
                        <span class="text-[11px] uppercase tracking-wider text-slate-400 font-semibold block">Nilai Kontrak</span>
                        <p id="mNilai" class="font-semibold text-blue-700 mt-0.5"></p>
                    </div>
                </div>
                <div>
                    <span class="text-[11px] uppercase tracking-wider text-slate-400 font-semibold block">Mitra / Pihak Kedua</span>
                    <p id="mMitra" class="font-semibold text-slate-900 mt-0.5"></p>
                </div>
                <div>
                    <span class="text-[11px] uppercase tracking-wider text-slate-400 font-semibold block">Isi Klausul Rahasia</span>
                    <div id="mKlausul" class="p-3.5 bg-slate-50 rounded-lg border border-slate-200 text-slate-700 mt-1 text-xs leading-relaxed"></div>
                </div>
                <div class="text-xs font-mono text-emerald-800 bg-emerald-50 p-3 rounded-lg border border-emerald-200">
                    RSA Digital Signature Terverifikasi: <span id="mSig" class="font-semibold"></span>
                </div>
            </div>
            <div class="px-6 py-3 bg-slate-50 border-t border-slate-200 flex justify-end">
                <button onclick="tutupModal()" class="bg-slate-800 hover:bg-slate-900 text-white text-xs font-semibold px-4 py-2 rounded-lg">Tutup Pratinjau</button>
            </div>
        </div>
    </div>

    <script>
        function bukaModalDekripsi(data) {
            document.getElementById('mNo').textContent = data.no;
            document.getElementById('mMitra').textContent = data.mitra;
            document.getElementById('mNilai').textContent = data.nilai;
            document.getElementById('mKlausul').textContent = data.klausul;
            document.getElementById('mSig').textContent = data.sig;
            const modal = document.getElementById('modalDekripsi');
            modal.classList.remove('hidden');
            modal.classList.add('flex');
        }
        function tutupModal() {
            const modal = document.getElementById('modalDekripsi');
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    </script>
</body>
</html>