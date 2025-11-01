#!/usr/bin/env python3
"""
scanner_console.py
Geliştirilmiş komut kabuğu (REPL) tarayıcı — IP aralığı ve hedef dosyası desteği ile.
"""
import cmd
import socket
import concurrent.futures
import csv
import time
import re
import ipaddress

def parse_ports(s):
    s = (s or "").replace(" ", "")
    parts = s.split(",")
    ports = set()
    for p in parts:
        if not p:
            continue
        if "-" in p:
            try:
                a, b = p.split("-", 1)
                a = int(a); b = int(b)
                if a > b:
                    a, b = b, a
                a = max(1, a); b = min(65535, b)
                ports.update(range(a, b+1))
            except ValueError:
                continue
        else:
            try:
                val = int(p)
                if 1 <= val <= 65535:
                    ports.add(val)
            except ValueError:
                continue
    return sorted(ports)

def expand_targets(spec):
    spec = (spec or "").strip()
    if not spec:
        return []
    # CIDR
    try:
        if '/' in spec:
            net = ipaddress.ip_network(spec, strict=False)
            return [str(ip) for ip in net.hosts()]
    except Exception:
        pass
    # range a-b
    if '-' in spec and not any(c.isalpha() for c in spec):
        try:
            a,b = spec.split('-',1)
            start = ipaddress.IPv4Address(a.strip())
            end = ipaddress.IPv4Address(b.strip())
            if int(start) > int(end):
                start, end = end, start
            alist = []
            cur = int(start)
            while cur <= int(end):
                alist.append(str(ipaddress.IPv4Address(cur)))
                cur += 1
            return alist
        except Exception:
            return []
    # single host (domain or IP)
    return [spec]

def check_port(host_ip, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((host_ip, port))
        if res == 0:
            try:
                sock.settimeout(0.6)
                sock.sendall(b"\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except Exception:
                banner = ""
            sock.close()
            return True, banner
        sock.close()
        return False, ""
    except Exception as e:
        return False, str(e)

class ScannerShell(cmd.Cmd):
    intro = "Geliştirilmiş scanner kabuğuna hoşgeldin. Yardım için 'help' yaz.\n"
    prompt = "scanner> "

    def __init__(self):
        super().__init__()
        self.target = None
        self.target_ip = None
        self.targets = []       # çoklu hedef desteği
        self.ports = [80, 443]
        self.timeout = 1.0
        self.max_workers = 50
        self.results = {}       # {(host,port): (open,banner)}
        self.last_run = None

    def do_set(self, arg):
        "set target <domain_or_ip>  -- tek hedef ayarlar"
        parts = arg.split()
        if len(parts) >= 2 and parts[0].lower() == "target":
            target = " ".join(parts[1:]).strip()
            if not target:
                print("Hedef boş bırakılamaz.")
                return
            try:
                ip = socket.gethostbyname(target)
                self.target = target
                self.target_ip = ip
                self.targets = [target]
                print(f"Hedef ayarlandı: {self.target} ({self.target_ip})")
            except Exception as e:
                print(f"DNS çözümlenemedi: {e}")
        else:
            print("Kullanım: set target example.com")

    def do_setrange(self, arg):
        "setrange <CIDR_or_range>  -- IP aralığı veya CIDR ile hedef listesi ayarlar"
        spec = arg.strip()
        if not spec:
            print("Kullanım: setrange 192.168.1.0/28 veya setrange 192.168.1.1-192.168.1.50")
            return
        targets = expand_targets(spec)
        if not targets:
            print("Geçersiz aralık.")
            return
        self.targets = targets
        print(f"{len(self.targets)} hedef ayarlandı (örnek: {self.targets[:3]}...)")

    def do_setfile(self, arg):
        "setfile <path>  -- dosyadan hedefleri oku (her satırda bir hedef)"
        path = arg.strip()
        if not path:
            print("Kullanım: setfile hedefler.txt")
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip()]
        except Exception as e:
            print(f"Dosya açılamadı: {e}")
            return
        self.targets = lines
        print(f"{len(self.targets)} hedef dosyadan yüklendi.")

    def do_ports(self, arg):
        "ports <liste|aralık>  -- portları ayarlar veya mevcut listeyi gösterir"
        if not arg.strip():
            print("Mevcut port listesi:", self.ports)
            return
        parsed = parse_ports(arg)
        if not parsed:
            print("Geçerli bir port listesi girin.")
            return
        self.ports = parsed
        print(f"Port listesi ayarlandı. {len(self.ports)} port.")

    def do_timeout(self, arg):
        "timeout <saniye>  -- bağlantı zaman aşımını ayarlar (float)"
        try:
            t = float(arg.strip())
            if t <= 0:
                raise ValueError()
            self.timeout = t
            print(f"Timeout ayarlandı: {self.timeout}s")
        except Exception:
            print("Geçerli bir sayı girin. Örnek: timeout 1.5")

    def do_workers(self, arg):
        "workers <adet>  -- paralel işçi sayısını ayarlar"
        try:
            n = int(arg.strip())
            if n < 1:
                raise ValueError()
            self.max_workers = min(200, n)
            print(f"Worker sayısı: {self.max_workers}")
        except Exception:
            print("Geçerli bir tam sayı girin. Örnek: workers 40")

    def _scan_host(self, host):
        try:
            ip = socket.gethostbyname(host)
        except Exception as e:
            print(f"{host} çözümlenemedi: {e}")
            return
        for p in self.ports:
            is_open, banner = check_port(ip, p, self.timeout)
            self.results[(host,p)] = (is_open, banner)
            if is_open:
                print(f"[OPEN] {host}:{p}  {('Banner: ' + banner) if banner else ''}")

    def do_scan(self, arg):
        "scan  -- ayarlı hedef(ler) ve portları tarar (tek veya çoklu hedef)"
        if not self.targets:
            print("Önce hedef ayarlayın: set target <host> veya setrange <CIDR/range> veya setfile <path>")
            return
        if not self.ports:
            print("Port listesi boş. Önce ports komutu ile portları ayarlayın.")
            return
        print(f"Toplam hedef: {len(self.targets)}  Port sayısı: {len(self.ports)}")
        self.results.clear()
        start = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(self.targets))) as exe:
            futures = [exe.submit(self._scan_host, h) for h in self.targets]
            try:
                for fut in concurrent.futures.as_completed(futures):
                    pass
            except KeyboardInterrupt:
                print("\n[!] Tarama kullanıcı tarafından durduruldu (Ctrl+C).")
        elapsed = time.time() - start
        self.last_run = time.ctime()
        print(f"\nTarama tamamlandı. Süre: {elapsed:.2f}s  ({self.last_run})")

    def do_show(self, arg):
        "show [all|open]  -- son tarama sonuçlarını gösterir (default all)"
        mode = arg.strip().lower() or "all"
        if not self.results:
            print("Henüz sonuç yok.")
            return
        print(f"Sonuçlar (hedef sayısı: {len(self.targets)}):")
        for (host,port) in sorted(self.results):
            is_open, banner = self.results[(host,port)]
            if mode == "open" and not is_open:
                continue
            status = "OPEN" if is_open else "closed"
            line = f"  {host}:{port} - {status}"
            if is_open and banner:
                line += f"  Banner: {banner}"
            print(line)

    def do_check(self, arg):
        "check <host> <port>  -- belirli host/port için kayıtlı bilgileri gösterir"
        parts = arg.split()
        if len(parts) != 2:
            print("Kullanım: check 192.168.1.10 22")
            return
        host, p = parts[0], parts[1]
        try:
            p = int(p)
        except Exception:
            print("Port tam sayı olmalı")
            return
        key = (host, p)
        if key not in self.results:
            print("Bu host/port için sonuç yok. Önce scan çalıştırın.")
            return
        is_open, banner = self.results[key]
        if not is_open:
            print(f"{host}:{p} kapalı.")
            return
        print(f"{host}:{p} açık. Banner: {banner}")

    def do_save(self, arg):
        "save <dosya.csv>  -- sonuçları CSV'ye kaydeder"
        filename = arg.strip() or "scan_results.csv"
        if not self.results:
            print("Kaydedilecek sonuç yok.")
            return
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["target", "ip", "port", "open", "banner"])
                for (host,port) in sorted(self.results):
                    is_open, banner = self.results[(host,port)]
                    try:
                        ip = socket.gethostbyname(host)
                    except Exception:
                        ip = ""
                    w.writerow([host, ip, port, is_open, banner])
            print(f"Kaydedildi: {filename}")
        except Exception as e:
            print(f"Dosya yazma hatası: {e}")

    def do_clear(self, arg):
        "clear  -- sadece önceki sonuçları temizler (targets ve ports korunur)"
        self.results.clear()
        print("Sonuçlar temizlendi. (targets ve ports korunuyor)")

    def do_exit(self, arg):
        "exit  -- çıkış"
        print("Çıkılıyor...")
        return True

    def do_quit(self, arg):
        "quit  -- alias for exit"
        return self.do_exit(arg)

    def emptyline(self):
        pass

    def do_EOF(self, arg):
        print(" (EOF) Çıkılıyor...")
        return True

if __name__ == '__main__':
    ScannerShell().cmdloop()

