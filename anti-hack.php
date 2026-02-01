<?php
/**
 * GuardSec FM (Defensive) - Malware/Webshell/Backdoor Scanner + Quarantine Manager
 * ------------------------------------------------------------------------------
 * ✅ Fokus DEFENSIVE: deteksi & bersihkan file berbahaya (webshell/backdoor/malware) di dalam ROOT.
 * ✅ UI dark neon mirip screenshot (tanpa terminal/upload/file-explorer bebas).
 *
 * Fitur:
 * - Login password + CSRF
 * - Set ROOT (batas aman) + folder picker (depth 4)
 * - Scan file "apapun" (tetap skip binary murni agar tidak berat, tapi detect PHP tag di file non-php)
 * - Heuristic scoring (high-confidence + chain rules)
 * - Actions: Preview, Download, Edit/Save (limit), Rename, Quarantine, Delete
 * - Bulk: Quarantine / Delete
 * - Quick Audit: cek .htaccess / .user.ini / php.ini lokal untuk auto_prepend_file dll
 *
 * SECURITY WAJIB:
 * 1) GANTI ADMIN_PASSWORD!
 * 2) Setelah selesai, HAPUS file ini dari server.
 */

@date_default_timezone_set('Asia/Phnom_Penh');
ini_set('max_execution_time', '0');
ini_set('memory_limit', '768M');
error_reporting(E_ALL);
session_start();

/* ================== CONFIG ================== */
const ADMIN_PASSWORD = 'GANTI_PASSWORD_KAMU_YANG_KUAT'; // <-- WAJIB GANTI
const DEFAULT_THRESHOLD = 14;      // 14-18 recommended (semakin tinggi = semakin ketat)
const MAX_FILE_SIZE_MB = 12;       // file maksimum yang dibaca saat scan
const PREVIEW_MAX_BYTES = 12000;
const EDIT_MAX_BYTES = 350000;     // editor max 350KB
const SESSION_KEY = 'guardsec_authed';
const TREE_MAX_DEPTH = 4;          // folder picker depth
/* ============================================= */

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function csrf_token(){
  if(empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
  return $_SESSION['csrf'];
}
function csrf_check(){
  $t = $_POST['csrf'] ?? '';
  return !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $t);
}
function is_authed(){ return !empty($_SESSION[SESSION_KEY]); }
function redirect_self($q=''){
  $url = strtok($_SERVER["REQUEST_URI"], '?');
  if($q) $url .= '?' . $q;
  header("Location: $url"); exit;
}
function flash($msg){ $_SESSION['flash'] = $msg; }
function get_flash(){
  $m = $_SESSION['flash'] ?? '';
  unset($_SESSION['flash']);
  return $m;
}
function normpath($p){
  $p = rtrim((string)$p, "/");
  $rp = realpath($p);
  if($rp !== false) return rtrim($rp, "/");
  return rtrim(preg_replace('#/+#','/', $p), "/");
}
function starts_with($hay, $needle){
  return substr($hay, 0, strlen($needle)) === $needle;
}
function safe_mkdir($dir){
  if(!is_dir($dir)) @mkdir($dir, 0755, true);
}
function file_ext($p){ return strtolower(pathinfo($p, PATHINFO_EXTENSION)); }
function refuse($msg){
  http_response_code(403);
  echo $msg;
  exit;
}

/* ===== Binary heuristics (scan "file apapun", tapi tetap aman/performance) ===== */
function is_probably_binary($content){
  // Jika ada null byte, besar kemungkinan binary murni
  return (strpos($content, "\0") !== false);
}
function looks_like_script_payload($content){
  // Marker script umum yang sering disisipkan (termasuk di file "gambar" palsu)
  return (bool)preg_match('/<\?(php|=)?|<%|<jsp:|#!/i', $content);
}

/* ---------------- LOGIN ---------------- */
if(isset($_GET['logout'])){
  session_destroy();
  redirect_self();
}
if(isset($_POST['action']) && $_POST['action']==='login'){
  if(!csrf_check()) refuse("CSRF fail");
  $pw = (string)($_POST['password'] ?? '');
  if(hash_equals(ADMIN_PASSWORD, $pw)){
    $_SESSION[SESSION_KEY] = 1;
    redirect_self();
  } else {
    flash("Password salah.");
    redirect_self();
  }
}
if(!is_authed()){
  $msg = get_flash();
  ?>
  <!doctype html><html><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GuardSec FM - Login</title>
    <style>
      body{font-family:system-ui,Arial;background:#050b18;color:#e8eefc;display:flex;min-height:100vh;align-items:center;justify-content:center;}
      .card{width:min(560px,92vw);background:#0b1326;border:1px solid #1a2b4a;border-radius:18px;padding:18px;box-shadow:0 0 25px #14b8ff33;}
      input{width:100%;padding:12px;border-radius:12px;border:1px solid #2a3b60;background:#071127;color:#e8eefc;}
      button{width:100%;padding:12px;border:0;border-radius:12px;background:#3b82f6;color:#fff;font-weight:900;cursor:pointer;}
      .muted{opacity:.85;font-size:13px;color:#9fb2d8;}
      .err{background:#3a1620;border:1px solid #7f1d1d;padding:10px;border-radius:12px;margin:10px 0;}
      code{background:#071127;padding:2px 6px;border-radius:10px;}
    </style>
  </head><body>
    <div class="card">
      <h2 style="margin:0 0 6px;">GuardSec FM</h2>
      <div class="muted">Mode defensive. Ganti <code>ADMIN_PASSWORD</code>. Setelah selesai, <b>hapus file panel</b>.</div>
      <?php if($msg): ?><div class="err"><?=h($msg)?></div><?php endif; ?>
      <form method="post">
        <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="login">
        <div class="muted" style="margin-top:10px;">Password</div>
        <input type="password" name="password" required placeholder="Password admin...">
        <div style="height:10px"></div>
        <button type="submit">Login</button>
      </form>
    </div>
  </body></html>
  <?php
  exit;
}

/* ===================== SCANNER CONFIG ===================== */

// Scan "file apapun": extension filter dimatikan
$scanExtensions = null;

// Folder berat/umum di-skip
$skipDirsRe = [
  '#/\.git(/|$)#',
  '#/node_modules(/|$)#',
  '#/vendor(/|$)#',
  '#/cache(/|$)#',
  '#/tmp(/|$)#',
  '#/wp-content/cache(/|$)#',
  '#/_quarantine_#',
];

/**
 * Heuristic patterns (wide coverage) - DEFENSIVE DETECTION.
 * Catatan: ini bukan "cara bikin webshell" — ini deteksi marker/behavior berbahaya.
 */
$patterns = [
  // High confidence execution
  ['re'=>'/\b(eval|assert)\s*\(/i', 'score'=>12, 'why'=>'eval/assert'],
  ['re'=>'/\b(system|shell_exec|passthru|exec|proc_open|popen|pcntl_exec)\s*\(/i', 'score'=>12, 'why'=>'os command'],
  ['re'=>'/`[^`]{1,400}`/s', 'score'=>10, 'why'=>'backtick exec'],
  ['re'=>'/preg_replace\s*\(\s*.*\/e\s*[\),]/i', 'score'=>14, 'why'=>'preg_replace /e'],

  // Obfuscation / unpack
  ['re'=>'/\b(base64_decode|gzinflate|gzuncompress|str_rot13|openssl_decrypt)\s*\(/i', 'score'=>8, 'why'=>'decode/unpack'],
  ['re'=>'/[A-Za-z0-9+\/]{250,}={0,2}/', 'score'=>6, 'why'=>'large base64 blob'],
  ['re'=>'/(?:\\\x[0-9a-fA-F]{2}){10,}/', 'score'=>6, 'why'=>'hex escape blob'],

  // Dynamic execution tricks
  ['re'=>'/\$\{[^}]{1,80}\}\s*\(/', 'score'=>14, 'why'=>'${var}('],
  ['re'=>'/\b(call_user_func|call_user_func_array)\s*\(/i', 'score'=>6, 'why'=>'call_user_func'],
  ['re'=>'/\b\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/i', 'score'=>16, 'why'=>'INPUT-as-function'],
  ['re'=>'/\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i', 'score'=>16, 'why'=>'$func($_INPUT)'],

  // Loader / remote fetch
  ['re'=>'/\b(file_get_contents|fopen)\s*\(\s*[\'"]https?:\/\//i', 'score'=>12, 'why'=>'remote fetch'],
  ['re'=>'/\b(curl_exec|curl_multi_exec)\s*\(/i', 'score'=>8, 'why'=>'curl exec'],
  ['re'=>'/\b(fsockopen|pfsockopen)\s*\(/i', 'score'=>8, 'why'=>'socket connect'],

  // Dropper / persistence hints (akan jadi kuat via chain)
  ['re'=>'/\b(file_put_contents|fwrite)\s*\(/i', 'score'=>6, 'why'=>'file write'],
  ['re'=>'/\b(move_uploaded_file|copy|rename)\s*\(/i', 'score'=>4, 'why'=>'file move/copy'],
  ['re'=>'/\b(unlink)\s*\(/i', 'score'=>4, 'why'=>'unlink'],
  ['re'=>'/\b(chmod|chown)\s*\(/i', 'score'=>6, 'why'=>'perm tamper'],

  // Dangerous wrappers / stealth
  ['re'=>'/php:\/\/input|data:\/\/text\/plain|expect:\/\//i', 'score'=>14, 'why'=>'php://input/wrappers'],
  ['re'=>'/@\s*(?:eval|assert|system|exec|shell_exec|passthru)\s*\(/i', 'score'=>10, 'why'=>'suppressed dangerous call'],
  ['re'=>'/\b(set_time_limit)\s*\(\s*0\s*\)/i', 'score'=>5, 'why'=>'infinite runtime'],

  // Known shell family keywords
  ['re'=>'/\b(wso|b374k|c99|r57|weevely|priv8|webshell|backdoor|FilesMan)\b/i', 'score'=>18, 'why'=>'known shell keyword'],

  // Script marker in any file
  ['re'=>'/<\?(php|=)?/i', 'score'=>10, 'why'=>'php tag marker'],
  ['re'=>'/<%/i', 'score'=>10, 'why'=>'asp marker'],
  ['re'=>'/#!/', 'score'=>4, 'why'=>'shebang marker'],
];

function should_skip_path($path, $skipDirsRe){
  foreach($skipDirsRe as $re){
    if(preg_match($re, $path)) return true;
  }
  return false;
}

function scan_score($content, $patterns){
  $score = 0; $hits = [];

  foreach($patterns as $p){
    if(preg_match($p['re'], $content)){
      $score += (int)$p['score'];
      $hits[] = $p['why'];
    }
  }

  // Chain rules (webshell/backdoor signatures)
  $hasInput = preg_match('/\$_(GET|POST|REQUEST|COOKIE)\s*\[/i', $content);
  $hasCmd   = preg_match('/\b(system|shell_exec|passthru|exec|proc_open|popen|pcntl_exec)\s*\(/i', $content) || preg_match('/`[^`]+`/s', $content);
  $hasEval  = preg_match('/\b(eval|assert)\s*\(/i', $content);
  $hasObf   = preg_match('/\b(base64_decode|gzinflate|gzuncompress|str_rot13|openssl_decrypt)\s*\(/i', $content);
  $hasDynFn = preg_match('/\$\{[^}]{1,80}\}\s*\(|\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i', $content);
  $hasRemote= preg_match('/\b(file_get_contents|fopen)\s*\(\s*[\'"]https?:\/\//i', $content) ||
             preg_match('/\b(curl_exec|curl_multi_exec|fsockopen|pfsockopen)\s*\(/i', $content);
  $hasWrite = preg_match('/\b(file_put_contents|fwrite)\s*\(/i', $content);
  $hasPhpIn = preg_match('/php:\/\/input/i', $content);

  if($hasInput && ($hasCmd || $hasEval || $hasDynFn)){
    $score += 18; $hits[] = 'CHAIN input->execute';
  }
  if($hasObf && ($hasCmd || $hasEval || $hasDynFn)){
    $score += 16; $hits[] = 'CHAIN obfuscation->execute';
  }
  if($hasRemote && $hasWrite){
    $score += 14; $hits[] = 'CHAIN remote->write (dropper)';
  }
  if($hasPhpIn && ($hasObf || $hasCmd || $hasEval || $hasDynFn)){
    $score += 14; $hits[] = 'CHAIN php://input->execute';
  }

  $hits = array_values(array_unique($hits));
  return [$score, $hits];
}

function quarantine_file($file, $root, $quarDir){
  $rel = ltrim(str_replace($root,'',$file), '/');
  $dest = $quarDir . '/' . $rel;
  safe_mkdir(dirname($dest));
  return @rename($file, $dest);
}

/* ---------------- State default ---------------- */
if(empty($_SESSION['root'])) $_SESSION['root'] = normpath(__DIR__);
if(empty($_SESSION['threshold'])) $_SESSION['threshold'] = DEFAULT_THRESHOLD;
if(!isset($_SESSION['selected_dirs'])) $_SESSION['selected_dirs'] = [];
if(empty($_SESSION['last_scan'])) $_SESSION['last_scan'] = [];
if(empty($_SESSION['quar_dir'])) $_SESSION['quar_dir'] = '';
if(empty($_SESSION['last_audit'])) $_SESSION['last_audit'] = [];

$ROOT = normpath($_SESSION['root']);

function ensure_in_root($file){
  $root = normpath($_SESSION['root']);
  $f = normpath($file);
  if(!$f || !starts_with($f, $root)) refuse("Refused: file outside ROOT.");
  return $f;
}

/* ---------------- Download endpoint ---------------- */
if(isset($_GET['download'])){
  $f = ensure_in_root($_GET['download']);
  if(!is_file($f)) refuse("File not found");
  $name = basename($f);
  header('Content-Type: application/octet-stream');
  header('Content-Disposition: attachment; filename="'.$name.'"');
  header('Content-Length: '.filesize($f));
  readfile($f);
  exit;
}

/* ---------------- AJAX endpoints ---------------- */
if(isset($_POST['action']) && in_array($_POST['action'], ['preview','read','save','rename'], true)){
  if(!csrf_check()) refuse("CSRF fail");

  $act = $_POST['action'];
  $file = ensure_in_root($_POST['file'] ?? '');
  if(!is_file($file)) refuse("File not found");

  header('Content-Type: application/json');

  if($act === 'preview'){
    $c = @file_get_contents($file, false, null, 0, PREVIEW_MAX_BYTES);
    if($c === false) $c = "(cannot read)";
    $c = str_replace("\0","\\0",$c);
    echo json_encode(["ok"=>1,"file"=>$file,"preview"=>$c], JSON_UNESCAPED_SLASHES);
    exit;
  }

  if($act === 'read'){
    $size = filesize($file);
    if($size > EDIT_MAX_BYTES){
      echo json_encode(["ok"=>0,"error"=>"File terlalu besar untuk editor (limit ".EDIT_MAX_BYTES." bytes)."], JSON_UNESCAPED_SLASHES);
      exit;
    }
    $c = @file_get_contents($file);
    if($c === false) $c = "";
    $c = str_replace("\0","\\0",$c);
    echo json_encode(["ok"=>1,"file"=>$file,"content"=>$c], JSON_UNESCAPED_SLASHES);
    exit;
  }

  if($act === 'save'){
    $size = filesize($file);
    if($size > EDIT_MAX_BYTES){
      echo json_encode(["ok"=>0,"error"=>"File terlalu besar untuk disimpan lewat panel (limit ".EDIT_MAX_BYTES." bytes)."], JSON_UNESCAPED_SLASHES);
      exit;
    }
    $content = (string)($_POST['content'] ?? '');
    $ok = @file_put_contents($file, $content);
    echo json_encode(["ok"=>$ok?1:0,"file"=>$file], JSON_UNESCAPED_SLASHES);
    exit;
  }

  if($act === 'rename'){
    $newName = trim((string)($_POST['newname'] ?? ''));
    if($newName === '' || strpos($newName,'/')!==false || strpos($newName,'\\')!==false){
      echo json_encode(["ok"=>0,"error"=>"Nama file tidak valid."], JSON_UNESCAPED_SLASHES);
      exit;
    }
    $dir = dirname($file);
    $dest = $dir . DIRECTORY_SEPARATOR . $newName;
    $dest = ensure_in_root($dest);
    if(file_exists($dest)){
      echo json_encode(["ok"=>0,"error"=>"Target sudah ada."], JSON_UNESCAPED_SLASHES);
      exit;
    }
    $ok = @rename($file, $dest);
    echo json_encode(["ok"=>$ok?1:0,"from"=>$file,"to"=>$dest], JSON_UNESCAPED_SLASHES);
    exit;
  }
}

/* ---------------- Actions (POST) ---------------- */
if(isset($_POST['action'])){
  if(!csrf_check()) refuse("CSRF fail");
  $act = $_POST['action'];

  if($act === 'set_root'){
    $root = normpath($_POST['root'] ?? __DIR__);
    if(!is_dir($root)){
      flash("ROOT tidak valid.");
      redirect_self();
    }
    $_SESSION['root'] = $root;
    $_SESSION['threshold'] = max(1, (int)($_POST['threshold'] ?? DEFAULT_THRESHOLD));
    $_SESSION['selected_dirs'] = [];
    $_SESSION['last_scan'] = [];
    $_SESSION['quar_dir'] = '';
    $_SESSION['last_audit'] = [];
    flash("ROOT diset: ".$root);
    redirect_self();
  }

  if($act === 'set_dirs'){
    $dirs = $_POST['dirs'] ?? [];
    $clean = [];
    foreach((array)$dirs as $d){
      $d = trim((string)$d);
      if($d === '') continue;
      if(strpos($d, '..') !== false) continue;
      $abs = normpath($_SESSION['root'] . '/' . $d);
      if(is_dir($abs) && starts_with($abs, normpath($_SESSION['root']))){
        $clean[] = $d;
      }
    }
    $_SESSION['selected_dirs'] = array_values(array_unique($clean));
    flash("Folder dipilih: ".count($_SESSION['selected_dirs'])." folder");
    redirect_self();
  }

  if($act === 'scan'){
    $root = normpath($_SESSION['root']);
    $threshold = (int)$_SESSION['threshold'];
    $maxBytes = (int)MAX_FILE_SIZE_MB * 1024 * 1024;

    $selected = $_SESSION['selected_dirs'];
    if(empty($selected)) $selected = ['.'];

    $ts = date("Ymd_His");
    $quarDir = $root . "/_quarantine_" . $ts;
    safe_mkdir($quarDir);

    $results = [];
    $scanned = 0; $flagged = 0;

    foreach($selected as $relDir){
      $scanDir = ($relDir === '.' ? $root : normpath($root . '/' . $relDir));
      if(!is_dir($scanDir)) continue;

      $rii = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($scanDir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
      );

      foreach($rii as $path => $info){
        if($info->isDir()){
          if(should_skip_path((string)$path, $skipDirsRe)) continue;
          continue;
        }

        $file = (string)$path;
        if(strpos($file, $quarDir) === 0) continue;
        if(should_skip_path($file, $skipDirsRe)) continue;

        $size = @filesize($file);
        if($size === false) $size = 0;
        if($size <= 0 || $size > $maxBytes) continue;

        // Read file
        $content = @file_get_contents($file);
        if($content === false) continue;

        // Skip binary murni (kecuali ada marker script)
        if(is_probably_binary($content) && !looks_like_script_payload($content)){
          continue;
        }

        $scanned++;
        [$score, $hits] = scan_score($content, $patterns);

        if($score >= $threshold){
          $flagged++;
          $results[] = [
            "file"=>$file,
            "ext"=>file_ext($file),
            "size"=>$size,
            "score"=>$score,
            "hits"=>$hits,
            "mtime"=>@filemtime($file) ?: 0,
            "sha1"=>@sha1_file($file) ?: '',
          ];
        }
      }
    }

    usort($results, fn($a,$b)=> $b['score'] <=> $a['score']);
    $_SESSION['last_scan'] = $results;
    $_SESSION['quar_dir'] = $quarDir;

    flash("SCAN selesai. Scanned: {$scanned} | Flagged: {$flagged} | Quarantine: {$quarDir}");
    redirect_self();
  }

  if($act === 'audit'){
    $root = normpath($_SESSION['root']);
    $files = [
      $root.'/.htaccess',
      $root.'/.user.ini',
      $root.'/php.ini',
      $root.'/wp-config.php',
    ];

    $findings = [];
    foreach($files as $f){
      if(!is_file($f)) continue;
      $c = @file_get_contents($f);
      if($c === false) continue;

      $sus = [];
      if(preg_match('/auto_prepend_file\s*=/i', $c)) $sus[] = 'auto_prepend_file';
      if(preg_match('/auto_append_file\s*=/i', $c)) $sus[] = 'auto_append_file';
      if(preg_match('/php:\/\/input/i', $c)) $sus[] = 'php://input';
      if(preg_match('/\b(base64_decode|gzinflate|eval|assert|system|shell_exec|passthru|exec)\b/i', $c)) $sus[] = 'dangerous keyword';
      if(preg_match('/RewriteRule\s+.*\.(?:jpg|png|gif|css|js)\s+\[.*E=.*\]/i', $c)) $sus[] = 'weird rewrite/env';
      if(preg_match('/AddHandler|SetHandler|php_value|php_flag/i', $c)) $sus[] = 'handler/php_value';

      if($sus){
        $findings[] = [
          'file'=>$f,
          'hits'=>$sus,
          'sha1'=>@sha1_file($f) ?: '',
          'mtime'=>@filemtime($f) ?: 0,
        ];
      }
    }

    $_SESSION['last_audit'] = $findings;
    flash("AUDIT selesai. Temuan: ".count($findings));
    redirect_self();
  }

  if($act === 'quarantine_one'){
    $file = ensure_in_root($_POST['file'] ?? '');
    $root = normpath($_SESSION['root']);
    $quarDir = (string)($_SESSION['quar_dir'] ?? '');
    if(!$quarDir || !is_dir($quarDir)){ flash("Quarantine folder belum ada. Scan dulu."); redirect_self(); }
    if(!is_file($file)){ flash("File tidak ditemukan."); redirect_self(); }

    $ok = quarantine_file($file, $root, $quarDir);
    flash($ok ? "OK: dipindah ke quarantine." : "Gagal (permission?).");
    $_SESSION['last_scan'] = array_values(array_filter($_SESSION['last_scan'], fn($r)=>$r['file']!==$file));
    redirect_self();
  }

  if($act === 'delete_one'){
    $file = ensure_in_root($_POST['file'] ?? '');
    if(!is_file($file)){ flash("File tidak ditemukan."); redirect_self(); }
    $ok = @unlink($file);
    flash($ok ? "OK: file dihapus." : "Gagal hapus (permission?).");
    $_SESSION['last_scan'] = array_values(array_filter($_SESSION['last_scan'], fn($r)=>$r['file']!==$file));
    redirect_self();
  }

  if($act === 'bulk_quarantine' || $act === 'bulk_delete'){
    $files = $_POST['files'] ?? [];
    $root = normpath($_SESSION['root']);
    $quarDir = (string)($_SESSION['quar_dir'] ?? '');

    $okN=0; $failN=0;
    foreach((array)$files as $f){
      $f = ensure_in_root($f);
      if(!is_file($f)){ $failN++; continue; }

      if($act === 'bulk_quarantine'){
        if(!$quarDir || !is_dir($quarDir)){ $failN++; continue; }
        if(quarantine_file($f, $root, $quarDir)) $okN++; else $failN++;
      } else {
        if(@unlink($f)) $okN++; else $failN++;
      }
    }

    $_SESSION['last_scan'] = array_values(array_filter($_SESSION['last_scan'], function($r) use($files){
      return !in_array($r['file'], (array)$files, true);
    }));

    flash(($act==='bulk_quarantine' ? "Bulk quarantine" : "Bulk delete") . " OK={$okN} FAIL={$failN}");
    redirect_self();
  }

  redirect_self();
}

/* ---------------- Folder tree builder ---------------- */
function list_dirs_tree($root, $maxDepth = TREE_MAX_DEPTH){
  $root = normpath($root);
  $out = [];
  $queue = [[ '.', $root, 0 ]];
  while($queue){
    [$rel, $abs, $depth] = array_shift($queue);
    if($depth > $maxDepth) continue;

    if(strpos($abs, '/_quarantine_') !== false) continue;

    $out[] = ['rel'=>$rel, 'abs'=>$abs, 'depth'=>$depth];

    $items = @scandir($abs);
    if(!$items) continue;

    foreach($items as $it){
      if($it==='.' || $it==='..') continue;
      $p = $abs . '/' . $it;
      if(is_dir($p)){
        $rp = normpath($p);
        if(preg_match('#/(node_modules|vendor|\.git|cache|tmp)(/|$)#', $rp)) continue;
        $rel2 = ($rel==='.' ? $it : $rel.'/'.$it);
        $queue[] = [$rel2, $rp, $depth+1];
      }
    }
  }
  return $out;
}

/* ---------------- Render UI ---------------- */
$ROOT = normpath($_SESSION['root']);
$threshold = (int)$_SESSION['threshold'];
$results = $_SESSION['last_scan'] ?? [];
$quarDir = $_SESSION['quar_dir'] ?? '';
$selectedDirs = $_SESSION['selected_dirs'] ?? [];
$audit = $_SESSION['last_audit'] ?? [];

$tree = is_dir($ROOT) ? list_dirs_tree($ROOT, TREE_MAX_DEPTH) : [];
$flashMsg = get_flash();

$serverIp = $_SERVER['SERVER_ADDR'] ?? '-';
$domain = $_SERVER['HTTP_HOST'] ?? '-';
$user = function_exists('get_current_user') ? get_current_user() : '-';
$os = defined('PHP_OS_FAMILY') ? PHP_OS_FAMILY : PHP_OS;

?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GuardSec FM</title>
  <style>
    :root{
      --bg1:#050b18; --bg2:#071021;
      --card:#0b1326; --border:#1a2b4a; --glow:#14b8ff33;
      --text:#e8eefc; --muted:#9fb2d8; --cyan:#00d0ff;
      --btn:#0c1a33; --btnb:#1b2f57;
      --blue:#3b82f6; --warn:#f59e0b; --bad:#ef4444;
    }
    body{
      margin:0; font-family:system-ui,Arial; color:var(--text);
      background:
        radial-gradient(1100px 500px at 50% -20%, #0d2a5a 0%, transparent 60%),
        radial-gradient(900px 500px at 30% 0%, #081a3c 0%, transparent 60%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
    }
    .wrap{max-width:1320px;margin:18px auto;padding:0 14px;}
    .card{
      background:linear-gradient(180deg, rgba(12,20,40,.95), rgba(9,16,32,.95));
      border:1px solid var(--border);
      box-shadow:0 0 0 1px #0b244433, 0 10px 40px #00000066, 0 0 25px var(--glow);
      border-radius:18px; padding:16px; margin-top:14px;
    }
    .brandbar{
      display:flex; align-items:center; justify-content:space-between; gap:14px; flex-wrap:wrap;
      padding:18px 18px;
      border-radius:18px;
      background:linear-gradient(180deg, rgba(10,16,30,.9), rgba(7,12,22,.9));
      border:1px solid var(--border);
      box-shadow:0 0 25px var(--glow);
    }
    .brand{display:flex; align-items:center; gap:12px;}
    .logo{
      width:44px;height:44px;border-radius:12px;
      display:grid;place-items:center;font-weight:900;color:#06101f;
      background:linear-gradient(135deg, #00d0ff, #1aa3ff);
      box-shadow:0 0 20px #00d0ff44;
    }
    .brandname{font-weight:900; font-size:20px;}
    .brandsub{color:var(--muted); font-size:12px; margin-top:2px;}
    .nav{display:flex; gap:10px; flex-wrap:wrap;}
    .navbtn{
      background:linear-gradient(180deg, var(--btn), #071127);
      border:1px solid var(--btnb);
      color:var(--cyan);
      padding:10px 14px;
      border-radius:12px;
      font-weight:900;
      cursor:pointer;
    }
    .navbtn.active{box-shadow:0 0 0 1px #00d0ff33, 0 0 18px #00d0ff22;}
    .homebtn{
      display:inline-block;padding:10px 16px;border-radius:12px;
      border:1px solid #2a3b60;background:linear-gradient(180deg, #0f1b35, #0a1226);
      color:#cfe2ff;font-weight:900;text-decoration:none;
    }

    .infogrid{
      display:grid; grid-template-columns: 1fr 1fr 1fr; gap:12px; margin-top:14px;
    }
    @media (max-width:1000px){.infogrid{grid-template-columns:1fr;}}
    .infocard{
      background:linear-gradient(180deg, rgba(9,16,32,.95), rgba(7,12,22,.95));
      border:1px solid var(--border);
      border-radius:16px;
      padding:14px;
      box-shadow:0 0 18px var(--glow);
    }
    .infotitle{color:var(--muted); font-size:12px; font-weight:900;}
    .infovalue{margin-top:6px; font-size:16px; font-weight:900; color:#dff6ff;}

    .flash{background:#102042;border:1px solid #1d3b6a;padding:10px;border-radius:14px;margin-top:14px;}
    .muted{color:var(--muted); font-size:13px;}
    input,textarea{
      padding:10px;border-radius:12px;border:1px solid #2a3b60;background:#071127;color:var(--text);width:100%;
    }
    textarea{min-height:240px;font-family:ui-monospace,Menlo,Consolas,monospace;}
    .row{display:grid;grid-template-columns: 1.4fr .4fr .7fr;gap:10px;}
    @media (max-width:900px){.row{grid-template-columns:1fr;}}
    .btn{padding:10px 12px;border:0;border-radius:12px;background:var(--blue);color:#fff;font-weight:900;cursor:pointer;}
    .btn2{padding:10px 12px;border:1px solid var(--btnb);border-radius:12px;background:linear-gradient(180deg, var(--btn), #071127);color:#cfe2ff;font-weight:900;cursor:pointer;}
    .btnWarn{background:var(--warn);color:#111827;font-weight:900;border:0;border-radius:12px;padding:10px 12px;cursor:pointer;}
    .btnBad{background:var(--bad);color:#fff;font-weight:900;border:0;border-radius:12px;padding:10px 12px;cursor:pointer;}
    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
    @media (max-width:1000px){.grid2{grid-template-columns:1fr;}}
    .dirlist{max-height:260px;overflow:auto;border:1px solid var(--border);border-radius:14px;background:#071127;padding:10px;}
    .diritem{display:flex;align-items:center;gap:8px;padding:4px 0;}
    .indent{display:inline-block;width:14px;}
    table{width:100%;border-collapse:collapse;}
    th,td{border-bottom:1px solid #22304f;padding:10px;vertical-align:top;font-size:13px;}
    th{color:var(--muted);text-align:left;font-weight:900;}
    .file{word-break:break-all;}
    .score{font-weight:900;}
    .score.bad{color:var(--bad);}
    .score.warn{color:var(--warn);}
    .hits{color:var(--muted);}
    .actions{display:flex;gap:8px;flex-wrap:wrap;}
    a{color:#93c5fd;text-decoration:none;}
    .small{font-size:12px;color:var(--muted);}
    .pill{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;border:1px solid var(--border);color:var(--muted);}
    .split{display:grid;grid-template-columns: 1.2fr .8fr;gap:12px;}
    @media (max-width:1100px){.split{grid-template-columns:1fr;}}
  </style>
</head>
<body>
<div class="wrap">

  <div class="brandbar">
    <div class="brand">
      <div class="logo">HS</div>
      <div>
        <div class="brandname">GuardSec FM</div>
        <div class="brandsub">Security Scanner v3.0 (Defensive)</div>
      </div>
    </div>

    <div class="nav">
      <button class="navbtn active" type="button">Files</button>
      <button class="navbtn" type="button" onclick="document.getElementById('scanForm').submit()">Search</button>
      <button class="navbtn" type="button" onclick="document.getElementById('scanForm').submit()">Tools</button>
      <button class="navbtn" type="button" onclick="alert('Terminal disabled in defensive mode.');">Terminal</button>
      <button class="navbtn" type="button" onclick="alert('Upload disabled in defensive mode.');">Upload</button>
    </div>

    <a class="homebtn" href="?logout=1">Home</a>
  </div>

  <div class="infogrid">
    <div class="infocard">
      <div class="infotitle">SERVER IP</div>
      <div class="infovalue"><?=h($serverIp)?></div>
    </div>
    <div class="infocard">
      <div class="infotitle">DOMAIN</div>
      <div class="infovalue"><?=h($domain)?></div>
    </div>
    <div class="infocard">
      <div class="infotitle">USER/OS</div>
      <div class="infovalue"><?=h($user)?> / <?=h($os)?></div>
    </div>
  </div>

  <?php if($flashMsg): ?><div class="flash"><?=h($flashMsg)?></div><?php endif; ?>

  <div class="card">
    <form method="post">
      <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="action" value="set_root">
      <div class="row">
        <div>
          <div class="muted">ROOT (batas aman). Semua aksi hanya boleh di dalam ROOT.</div>
          <input name="root" value="<?=h($ROOT)?>" placeholder="/home/USER/public_html">
          <div class="small" style="margin-top:8px;">
            Mode scan: <b>file apapun</b> (binary murni di-skip, kecuali ada marker script).
          </div>
        </div>
        <div>
          <div class="muted">Threshold</div>
          <input name="threshold" type="number" min="1" value="<?=h($threshold)?>">
          <div class="small" style="margin-top:8px;">Rekomendasi: 14–18</div>
        </div>
        <div style="display:flex; gap:10px; align-items:end; flex-wrap:wrap;">
          <button class="btn2" type="submit">Simpan Setting</button>
          <button class="btn" type="button" onclick="document.getElementById('scanForm').submit()">SCAN</button>
          <button class="btn2" type="button" onclick="document.getElementById('auditForm').submit()">Quick Audit</button>
        </div>
      </div>
    </form>

    <form id="scanForm" method="post" style="display:none;">
      <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="action" value="scan">
    </form>

    <form id="auditForm" method="post" style="display:none;">
      <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
      <input type="hidden" name="action" value="audit">
    </form>

    <div class="muted" style="margin-top:10px;">
      <span class="pill">ROOT: <?=h($ROOT)?></span>
      <span class="pill">Threshold: <?=h($threshold)?></span>
      <span class="pill">Quarantine: <?=h($quarDir ?: '(belum ada)')?></span>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <h3 style="margin:0 0 6px;">Pilih Folder yang Mau Di-scan</h3>
      <div class="muted">Centang folder tertentu. Kalau tidak memilih apa-apa, default scan ROOT.</div>

      <form method="post" style="margin-top:10px;">
        <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" value="set_dirs">

        <div class="dirlist">
          <?php foreach($tree as $d): ?>
            <?php
              $rel = $d['rel'];
              $depth = (int)$d['depth'];
              $checked = in_array($rel, $selectedDirs, true);
              $label = ($rel==='.' ? '[ROOT]' : $rel);
            ?>
            <div class="diritem">
              <?php for($i=0;$i<$depth;$i++) echo '<span class="indent"></span>'; ?>
              <input type="checkbox" name="dirs[]" value="<?=h($rel)?>" <?= $checked ? 'checked' : '' ?>>
              <span><?=h($label)?></span>
            </div>
          <?php endforeach; ?>
        </div>

        <div class="actions" style="margin-top:10px;">
          <button class="btn2" type="button" onclick="toggleDir(true)">Select All</button>
          <button class="btn2" type="button" onclick="toggleDir(false)">Unselect All</button>
          <button class="btn" type="submit">Simpan Pilihan Folder</button>
        </div>
        <div class="small">Picker sampai depth <?=h((string)TREE_MAX_DEPTH)?> level.</div>
      </form>
    </div>

    <div class="card">
      <h3 style="margin:0 0 6px;">File Actions (Defensive)</h3>
      <div class="muted">Klik Preview / Edit / Rename / Download / Quarantine / Delete dari hasil scan.</div>

      <div style="margin-top:10px;">
        <div class="muted"><b>Preview</b></div>
        <pre id="pvBody" style="white-space:pre-wrap;word-break:break-word;background:#071127;border:1px solid #22304f;border-radius:14px;padding:10px;margin:6px 0 0;min-height:120px;">Klik tombol Preview di tabel hasil scan.</pre>
      </div>

      <div style="margin-top:10px;">
        <div class="muted"><b>Editor</b> (limit <?=h((string)EDIT_MAX_BYTES)?> bytes)</div>
        <textarea id="edBody" placeholder="Klik Edit untuk load isi file..."></textarea>
        <div class="actions" style="margin-top:10px;">
          <button class="btn2" type="button" onclick="loadEdit()">Edit (Load)</button>
          <button class="btn" type="button" onclick="saveEdit()">Save</button>
        </div>
        <div class="small" id="edInfo">File aktif: (belum ada)</div>
      </div>

      <div style="margin-top:10px;">
        <div class="muted"><b>Rename</b></div>
        <input id="rnNew" placeholder="nama_baru.ext">
        <div class="actions" style="margin-top:10px;">
          <button class="btnWarn" type="button" onclick="doRename()">Rename</button>
        </div>
        <div class="small" id="rnInfo">File aktif: (belum ada)</div>
      </div>
    </div>
  </div>

  <div class="card">
    <div style="display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;">
      <h3 style="margin:0;">Quick Audit (Config Persistence)</h3>
      <div class="muted">Cek indikasi persist: <code>.htaccess</code>, <code>.user.ini</code>, <code>php.ini</code>, <code>wp-config.php</code></div>
    </div>

    <?php if(empty($audit)): ?>
      <div class="muted" style="margin-top:10px;">Belum ada audit. Klik “Quick Audit”.</div>
    <?php else: ?>
      <table style="margin-top:10px;">
        <thead>
          <tr>
            <th>File</th>
            <th>Indikasi</th>
            <th style="width:220px;">Meta</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach($audit as $a):
            $mtime = $a['mtime'] ? date('Y-m-d H:i:s', $a['mtime']) : '-';
          ?>
          <tr>
            <td class="file"><b><?=h($a['file'])?></b></td>
            <td class="hits"><?=h(implode(', ', $a['hits']))?></td>
            <td class="muted">mtime: <?=h($mtime)?> | sha1: <?=h($a['sha1'])?></td>
          </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>

  <div class="card">
    <div style="display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;">
      <h3 style="margin:0;">Hasil Scan (<?=count($results)?> file ter-flag)</h3>
      <div class="muted">Centang → Bulk Quarantine / Bulk Delete</div>
    </div>

    <?php if(empty($results)): ?>
      <div class="muted" style="margin-top:10px;">Belum ada hasil scan. Klik SCAN dulu.</div>
    <?php else: ?>

      <form method="post" id="bulkForm">
        <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
        <input type="hidden" name="action" id="bulkAction" value="bulk_quarantine">

        <div class="actions" style="margin:10px 0;">
          <button class="btnWarn" type="button" onclick="setBulk('bulk_quarantine')">Bulk Quarantine</button>
          <button class="btnBad" type="button" onclick="if(confirm('Yakin hapus permanen?')) setBulk('bulk_delete')">Bulk Delete</button>
          <button class="btn2" type="button" onclick="toggleAll(true)">Select All</button>
          <button class="btn2" type="button" onclick="toggleAll(false)">Unselect All</button>
        </div>

        <table>
          <thead>
            <tr>
              <th style="width:34px;"></th>
              <th>File</th>
              <th style="width:90px;">Ext</th>
              <th style="width:90px;">Size</th>
              <th style="width:70px;">Score</th>
              <th>Alasan</th>
              <th style="width:460px;">Aksi</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach($results as $r):
              $score = (int)$r['score'];
              $cls = $score >= 26 ? 'bad' : 'warn';
              $sizeKB = round($r['size']/1024, 1);
              $mtime = $r['mtime'] ? date('Y-m-d H:i:s', $r['mtime']) : '-';
            ?>
            <tr>
              <td><input class="chk" type="checkbox" name="files[]" value="<?=h($r['file'])?>"></td>
              <td class="file">
                <div><b><?=h($r['file'])?></b></div>
                <div class="muted">mtime: <?=h($mtime)?> | sha1: <?=h($r['sha1'])?></div>
              </td>
              <td><?=h($r['ext'] ?: '-')?></td>
              <td><?=h($sizeKB)?> KB</td>
              <td><span class="score <?=h($cls)?>"><?=h($score)?></span></td>
              <td class="hits"><?=h(implode(', ', $r['hits']))?></td>
              <td>
                <div class="actions">
                  <button class="btn2" type="button" onclick="setActive('<?=h(addslashes($r['file']))?>'); previewActive();">Preview</button>
                  <button class="btn2" type="button" onclick="setActive('<?=h(addslashes($r['file']))?>'); loadEdit();">Edit</button>
                  <a class="btn2" href="?download=<?=h(urlencode($r['file']))?>" onclick="return confirm('Download file ini?')">Download</a>

                  <form method="post" style="display:inline;">
                    <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
                    <input type="hidden" name="action" value="quarantine_one">
                    <input type="hidden" name="file" value="<?=h($r['file'])?>">
                    <button class="btnWarn" type="submit">Quarantine</button>
                  </form>

                  <form method="post" style="display:inline;">
                    <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
                    <input type="hidden" name="action" value="delete_one">
                    <input type="hidden" name="file" value="<?=h($r['file'])?>">
                    <button class="btnBad" type="submit" onclick="return confirm('Yakin hapus permanen?')">Delete</button>
                  </form>

                  <button class="btnWarn" type="button" onclick="setActive('<?=h(addslashes($r['file']))?>'); askRename();">Rename</button>
                </div>
              </td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </form>

      <div class="muted" style="margin-top:10px;">
        Saran aman: <b>quarantine dulu</b> file score tinggi → cek site normal → baru delete permanen.
      </div>

    <?php endif; ?>
  </div>

  <div class="muted" style="margin:14px 0;">
    Setelah selesai: <b>hapus file panel ini</b> dari server.
  </div>
</div>

<script>
  const CSRF = "<?=h(csrf_token())?>";
  let ACTIVE = "";

  function toggleAll(on){ document.querySelectorAll('.chk').forEach(x=>x.checked=on); }
  function toggleDir(on){ document.querySelectorAll('.dirlist input[type="checkbox"]').forEach(x=>x.checked=on); }

  function setBulk(action){
    document.getElementById('bulkAction').value = action;
    document.getElementById('bulkForm').submit();
  }

  function setActive(file){
    ACTIVE = file;
    document.getElementById('edInfo').textContent = "File aktif: " + file;
    document.getElementById('rnInfo').textContent = "File aktif: " + file;
  }

  async function postJSON(action, payload){
    const form = new FormData();
    form.append('csrf', CSRF);
    form.append('action', action);
    for(const k in payload) form.append(k, payload[k]);
    const res = await fetch(location.href, { method:'POST', body: form });
    const txt = await res.text();
    try{ return JSON.parse(txt); }catch(e){ return {ok:0, error:"Invalid JSON", raw:txt}; }
  }

  async function previewActive(){
    if(!ACTIVE){ alert("Pilih file dulu."); return; }
    const j = await postJSON('preview', { file: ACTIVE });
    document.getElementById('pvBody').textContent = j.ok ? j.preview : (j.error || j.raw || "error");
  }

  async function loadEdit(){
    if(!ACTIVE){ alert("Pilih file dulu."); return; }
    const j = await postJSON('read', { file: ACTIVE });
    if(j.ok){
      document.getElementById('edBody').value = j.content;
    } else {
      alert(j.error || "Gagal load file.");
    }
  }

  async function saveEdit(){
    if(!ACTIVE){ alert("Pilih file dulu."); return; }
    if(!confirm("Yakin simpan perubahan?")) return;
    const content = document.getElementById('edBody').value;
    const j = await postJSON('save', { file: ACTIVE, content });
    alert(j.ok ? "Tersimpan." : (j.error || "Gagal simpan."));
  }

  function askRename(){
    if(!ACTIVE){ alert("Pilih file dulu."); return; }
    const bn = ACTIVE.split('/').pop();
    document.getElementById('rnNew').value = bn;
    document.getElementById('rnNew').focus();
  }

  async function doRename(){
    if(!ACTIVE){ alert("Pilih file dulu."); return; }
    const newname = document.getElementById('rnNew').value.trim();
    if(!newname){ alert("Isi nama baru."); return; }
    if(!confirm("Rename file jadi: " + newname + " ?")) return;
    const j = await postJSON('rename', { file: ACTIVE, newname });
    if(j.ok){
      alert("Renamed:\n" + j.from + "\n->\n" + j.to + "\nRefresh halaman untuk update tabel.");
      setActive(j.to);
    } else {
      alert(j.error || "Gagal rename.");
    }
  }
</script>
</body>
</html>
