<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WHOIS Sorgulama (Veritabanı Yok)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
</head>
<body>
<div class="container mt-5">
    <h2 class="text-center mb-4">Domain WHOIS Sorgulama (Veritabanı Yok)</h2>

    <?php
    // Hata raporlaması (geliştirme aşamasında)
    error_reporting(E_ALL);
    ini_set('display_errors', 1);

    // Form gönderildi mi?
    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['domains'])) {
        $domains = $_POST['domains'];
        $tlds = $_POST['tlds'] ?? [];

        foreach ($domains as $index => $domain) {
            $domain = trim($domain);
            $tld = isset($tlds[$index]) ? trim($tlds[$index]) : '';

            if (!empty($domain) && !empty($tld)) {
                $fullDomain = $domain . "." . $tld;

                // Doğrudan WHOIS sorgusu (thin whois desteğiyle)
                $whoisData = performWhoisQuery($fullDomain);

                // Domain boşta mı?
                // "No match", "NOT FOUND" vb. içeriklere bakarak basit bir kontrol
                $available = (stripos($whoisData, 'No match') !== false || 
                              stripos($whoisData, 'NOT FOUND') !== false)
                            ? 'Domain boşta'
                            : 'Domain kayıtlı';

                // WHOIS verisinden parse edilebilecek alanlar
                $registrar     = parseWhoisData($whoisData, ['Registrar:', 'Registrar Name:', 'registrar:']);
                $creationDate  = parseWhoisData($whoisData, ['Creation Date:', 'Created On:', 'Domain Registration Date:']);
                $expiryDate    = parseWhoisData($whoisData, ['Registry Expiry Date:', 'Expiration Date:', 'Expiry date:']);
                $status        = parseWhoisData($whoisData, ['Domain Status:', 'Status:']);
                $nameservers   = parseWhoisData($whoisData, ['Name Server:', 'Nameservers:']);
                $dnssec        = parseWhoisData($whoisData, ['DNSSEC:']);
                $owner         = parseWhoisData($whoisData, ['Registrant Name:', 'Owner Name:', 'Registrant:']);
                $ownerEmail    = parseWhoisData($whoisData, ['Registrant Email:', 'Owner Email:']);
                $ownerPhone    = parseWhoisData($whoisData, ['Registrant Phone:', 'Phone:']);

                // Ekrana yazdır
                echo '<h3 class="mt-5">Sorgu Sonuçları: ' . htmlspecialchars($fullDomain) . '</h3>';
                echo '<p><strong>' . $available . '</strong></p>';
                echo '<table class="table table-striped mt-3">
                        <tr><th>Registrar</th><td>' . $registrar . '</td></tr>
                        <tr><th>Kayıt Tarihi</th><td>' . $creationDate . '</td></tr>
                        <tr><th>Bitiş Tarihi</th><td>' . $expiryDate . '</td></tr>
                        <tr><th>Durum</th><td>' . $status . '</td></tr>
                        <tr><th>DNSSEC</th><td>' . $dnssec . '</td></tr>
                        <tr><th>Ad Sunucuları</th><td>' . $nameservers . '</td></tr>
                        <tr><th>Sahibi</th><td>' . $owner . '</td></tr>
                        <tr><th>Sahip E-posta</th><td>' . $ownerEmail . '</td></tr>
                        <tr><th>Sahip Telefon</th><td>' . $ownerPhone . '</td></tr>
                      </table>';

                // JSON log
                logDomainSearch($fullDomain, $whoisData);
            }
        }
    }

    // -------------------------------------------------------------
    // WHOIS sorgusu (thin whois destekli)
    // -------------------------------------------------------------
    function performWhoisQuery($domain) {
        $whoisServers = getWhoisServers();
        $domainParts = explode('.', $domain);
        $tld = strtolower(array_pop($domainParts));

        if (!isset($whoisServers[$tld])) {
            return "Bu TLD için WHOIS sunucusu bulunamadı veya desteklenmiyor.";
        }

        // 1) İlk sorgu (ör: whois.verisign-grs.com)
        $primaryServer = $whoisServers[$tld];
        $response = queryWhoisServer($primaryServer, $domain);

        // 2) "Thin WHOIS" – Registrar WHOIS Server satırını arayalım
        if (preg_match('/Registrar WHOIS Server:\s*(.+)/i', $response, $matches)) {
            $secondaryServer = trim($matches[1]);
            // Bazı durumlarda "unavailable" vb. olabilir
            if (!empty($secondaryServer) && stripos($secondaryServer, 'unavailable') === false) {
                $secondResponse = queryWhoisServer($secondaryServer, $domain);
                // Eğer ikinci yanıt daha faydalı ise, onu esas al
                if (!empty($secondResponse) && stripos($secondResponse, 'No match') === false) {
                    $response = $secondResponse;
                }
            }
        }

        return $response;
    }

    // -------------------------------------------------------------
    // Tek seferlik WHOIS sunucusuna bağlanma
    // -------------------------------------------------------------
    function queryWhoisServer($whoisServer, $domain) {
        $port = 43;
        $timeout = 10; // saniye

        $fp = @fsockopen($whoisServer, $port, $errno, $errstr, $timeout);
        if (!$fp) {
            return "WHOIS sunucusuna bağlanılamadı: $errstr ($errno)";
        }

        fputs($fp, $domain."\r\n");
        $out = "";
        while(!feof($fp)) {
            $out .= fgets($fp, 128);
        }
        fclose($fp);

        return $out;
    }

    // -------------------------------------------------------------
    // WHOIS metninden alanları ayıklama
    // -------------------------------------------------------------
    function parseWhoisData($whoisText, array $possibleLabels) {
        foreach ($possibleLabels as $label) {
            $pattern = '/'.$label.'\s*(.*)/i';
            if (preg_match($pattern, $whoisText, $match)) {
                return trim($match[1]);
            }
        }
        return "Bulunamadı";
    }

    // -------------------------------------------------------------
    // TLD => whois server eşlemesi (kısaltılmış liste)
    // -------------------------------------------------------------
    function getWhoisServers() {
        return [
            "com" => "whois.verisign-grs.com",
            "net" => "whois.verisign-grs.com",
            "org" => "whois.pir.org",
            "io"  => "whois.nic.io",
            "co"  => "whois.nic.co",
            "info"=> "whois.afilias.net",
            "ac"  => "whois.nic.ac",
            // ... ihtiyaca göre ekleyebilirsiniz ...
        ];
    }

    // -------------------------------------------------------------
    // JSON log fonksiyonu
    // -------------------------------------------------------------
    function logDomainSearch($domain, $whoisData) {
        $filename = 'search.json';

        // Mevcut JSON içeriğini yükle
        $data = [];
        if (file_exists($filename)) {
            $contents = file_get_contents($filename);
            if (!empty($contents)) {
                $decoded = json_decode($contents, true);
                if (is_array($decoded)) {
                    $data = $decoded;
                }
            }
        }

        // Yeni kayıt oluştur
        $newEntry = [
            'domain'    => $domain,
            'timestamp' => date('Y-m-d H:i:s'),
            // WHOIS verisini komple eklemek isterseniz, boyutu büyük olabilir.
            // Örnek olarak 300 karakterle kısaltıyorum.
            'raw_whois' => mb_substr($whoisData, 0, 300)
        ];
        $data[] = $newEntry;

        // 1000 kayda ulaştı mı?
        if (count($data) >= 1000) {
            // Dosyayı search2.json'a taşı
            file_put_contents('search2.json', json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            // search.json'u sıfırla
            file_put_contents($filename, json_encode([], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        } else {
            // search.json'u güncelle
            file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        }
    }
    ?>

    <!-- Form -->
    <form method="POST" action="">
        <table class="table table-bordered" id="domainTable">
            <thead>
            <tr>
                <th></th> <!-- Domain ekleme butonu için boş sütun -->
                <th>Domain Adı</th>
                <th>TLD Seçin</th>
            </tr>
            </thead>
            <tbody>
            <tr>
                <td>
                    <button type="button" class="btn btn-success btn-sm" id="addRow">+</button>
                </td>
                <td><input type="text" class="form-control" name="domains[]" placeholder="example" required></td>
                <td>
                    <select class="form-select tld-select" name="tlds[]">
                        <option value="com">.com</option>
                        <option value="net">.net</option>
                        <option value="org">.org</option>
                        <option value="io">.io</option>
                        <option value="co">.co</option>
                        <option value="info">.info</option>
                        <option value="ac">.ac</option>
                    </select>
                </td>
            </tr>
            </tbody>
        </table>
        <button type="submit" class="btn btn-primary">Sorgula</button>
    </form>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
<script>
    // Dinamik yeni satır ekleme
    document.getElementById('addRow').addEventListener('click', function() {
        const table = document.getElementById('domainTable').getElementsByTagName('tbody')[0];
        const newRow = table.insertRow();

        const addButtonCell = newRow.insertCell(0);
        const domainCell = newRow.insertCell(1);
        const tldCell = newRow.insertCell(2);

        // Boş hücreye yine + butonu koyabilir veya tamamen kaldırabilirsiniz.
        addButtonCell.innerHTML = '<button type="button" class="btn btn-success btn-sm" id="addRow">+</button>';
        domainCell.innerHTML = '<input type="text" class="form-control" name="domains[]" placeholder="example" required>';
        tldCell.innerHTML = `
            <select class="form-select tld-select" name="tlds[]">
                <option value="com">.com</option>
                <option value="net">.net</option>
                <option value="org">.org</option>
                <option value="io">.io</option>
                <option value="co">.co</option>
                <option value="info">.info</option>
                <option value="ac">.ac</option>
            </select>
        `;

        // Select2 uygula (yeni eklenen satıra)
        $('.tld-select').select2();
    });

    // İlk satırdaki select'e de Select2 uygulama
    $('.tld-select').select2({
        placeholder: 'TLD seçin',
        allowClear: true
    });
</script>
</body>
</html>
