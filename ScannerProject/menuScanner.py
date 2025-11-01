#!/usr/bin/env python3
"""
menu_scanner.py

Menü tabanlı taşınabilir port ve IP tarayıcı.
FSociety-style banner ile başlar: "54society" (54 kısmı renkli).

Kullanım:
    python menu_scanner.py           # varsayılan renk: green
    python menu_scanner.py --color red

UYARI: Yalnızca izniniz olan hedeflerde kullanın. İzinsiz tarama yasa dışıdır.
"""
from __future__ import annotations

import socket
import ipaddress
import argparse
import sys
from typing import List, Tuple

COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,587,8080,8443,3306,3389]

# ----------------------------
# Banner (FSociety-like "54society")
# ----------------------------
def print_banner(color: str = "green") -> None:
    """
    color: "green" or "red"
    """
    GREEN = "\033[32m"
    RED   = "\033[31m"
    BOLD  = "\033[1m"
    END   = "\033[0m"

    col = GREEN if color.lower() == "green" else RED
    try:
        # If colorama is installed (Windows), init for proper color handling
        import colorama  # type: ignore
        colorama.init()
    except Exception:
        pass

    logo_lines = [
        f"{col}54{END}society       _____ ____   ____  _____",
        f"{col}54{END}society      |  ___|  _ \\ / ___|| ____|",
        f"{col}54{END}society      | |_  | | | | |  _ |  _|",
        f"{col}54{END}society      |  _| | |_| | |_| || |___",
        f"{col}54{END}society      |_|   |____/ \\____||_____|",
    ]
    header = f"{BOLD}{col}DarkScanner — 54society Edition{END}\n"
    print(header + "\n".join(logo_lines) + "\n")
    print("Eğitim amaçlıdır — yalnızca izinli hedeflerde kullanın.\n")

# ----------------------------
# Networking helpers
# ----------------------------
def scan_port(host: str, port: int, timeout: float = 0.6) -> Tuple[bool, str]:
    """
    Basit TCP connect port scan. Return (is_open, banner_or_error).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((host, port))
        if res == 0:
            # try to grab a small banner
            banner = ""
            try:
                sock.settimeout(0.4)
                # send simple newline to provoke banner for some services
                sock.sendall(b"\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except Exception:
                banner = ""
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            return True, banner
        try:
            sock.close()
        except Exception:
            pass
        return False, ""
    except Exception as e:
        return False, str(e)

def expand_targets(spec: str) -> List[str]:
    """
    Desteklenen formatlar:
      - Tek host: "example.com" veya "192.168.1.10"
      - Aralık: "192.168.1.1-192.168.1.50"
      - CIDR: "192.168.1.0/28"
    """
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
    # range a-b (IPv4)
    if '-' in spec and not any(c.isalpha() for c in spec):
        try:
            a, b = spec.split('-', 1)
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
            pass
    # single host (domain or ip)
    return [spec]

# ----------------------------
# Menu operations
# ----------------------------
def single_port_scan() -> None:
    hedef = input("Hedef IP veya domain girin: ").strip()
    if not hedef:
        print("Hedef boş. İptal.")
        return
    try:
        ip = socket.gethostbyname(hedef)
    except Exception as e:
        print(f"DNS çözümlenemedi: {e}")
        return
    try:
        port = int(input("Taranacak port (ör. 80): ").strip() or "80")
    except ValueError:
        print("Geçersiz port.")
        return
    print(f"{hedef} ({ip}) üzerinde port {port} taranıyor...")
    is_open, banner = scan_port(ip, port)
    if is_open:
        print(f"[+] {port} açık. Banner: {banner if banner else '(yok)'}")
    else:
        print(f"[-] {port} kapalı veya yanıtsız")

def port_range_scan() -> None:
    hedef = input("Hedef IP veya domain girin: ").strip()
    if not hedef:
        print("Hedef boş. İptal.")
        return
    try:
        ip = socket.gethostbyname(hedef)
    except Exception as e:
        print(f"DNS çözümlenemedi: {e}")
        return
    try:
        bas_port = int(input("Başlangıç portu: ").strip())
        bit_port = int(input("Bitiş portu: ").strip())
    except ValueError:
        print("Geçersiz port aralığı.")
        return
    if bas_port > bit_port:
        bas_port, bit_port = bit_port, bas_port
    print(f"{hedef} ({ip}) üzerinde {bas_port}-{bit_port} aralığı taranıyor...")
    try:
        for port in range(bas_port, bit_port + 1):
            is_open, banner = scan_port(ip, port)
            if is_open:
                print(f"[OPEN] {port}  {('Banner: ' + banner) if banner else ''}")
    except KeyboardInterrupt:
        print("\n[!] Tarama durduruldu (Ctrl+C).")

def common_ports_scan() -> None:
    hedef = input("Hedef IP veya domain girin: ").strip()
    if not hedef:
        print("Hedef boş. İptal.")
        return
    try:
        ip = socket.gethostbyname(hedef)
    except Exception as e:
        print(f"DNS çözümlenemedi: {e}")
        return
    print(f"{hedef} ({ip}) üzerinde yaygın portlar taranıyor...")
    try:
        for p in COMMON_PORTS:
            is_open, banner = scan_port(ip, p)
            if is_open:
                print(f"[OPEN] {p}  {('Banner: ' + banner) if banner else ''}")
    except KeyboardInterrupt:
        print("\n[!] Tarama durduruldu (Ctrl+C).")

def ip_range_scan() -> None:
    spec = input("IP aralığı veya CIDR girin (örn. 192.168.1.1-192.168.1.50 veya 192.168.1.0/28): ").strip()
    targets = expand_targets(spec)
    if not targets:
        print("Geçerli bir aralık girin.")
        return
    ports_raw = input("Port(lar) (virgülle veya aralıkla: 22,80,1000-1010) [boş=COMMON_PORTS]: ").strip()
    if not ports_raw:
        ports = COMMON_PORTS.copy()
    else:
        ports = []
        for part in ports_raw.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                try:
                    a,b = part.split('-',1)
                    a=int(a); b=int(b)
                    if a>b: a,b = b,a
                    ports.extend(range(max(1,a), min(65535,b)+1))
                except Exception:
                    continue
            else:
                try:
                    v=int(part)
                    ports.append(v)
                except Exception:
                    continue
    ports = sorted(set(ports))
    print(f"{len(targets)} host taranıyor, her host için {len(ports)} port...")
    try:
        for host in targets:
            try:
                ip = socket.gethostbyname(host)
            except Exception as e:
                print(f"{host} çözümlenemedi: {e}")
                continue
            print(f"\n--- {host} ({ip}) taranıyor ---")
            for p in ports:
                is_open, banner = scan_port(ip, p)
                if is_open:
                    print(f"[OPEN] {host}:{p}  {('Banner: ' + banner) if banner else ''}")
    except KeyboardInterrupt:
        print("\n[!] IP aralığı taraması durduruldu.")

def scan_from_file() -> None:
    path = input("Hedef dosyası yolunu gir (her satırda bir IP/domain): ").strip()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception as e:
        print(f"Dosya açılamadı: {e}")
        return
    ports_raw = input("Port(lar) (virgülle veya aralıkla) [boş=COMMON_PORTS]: ").strip()
    if not ports_raw:
        ports = COMMON_PORTS.copy()
    else:
        ports = []
        for part in ports_raw.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                try:
                    a,b = part.split('-',1)
                    a=int(a); b=int(b)
                    if a>b: a,b = b,a
                    ports.extend(range(max(1,a), min(65535,b)+1))
                except Exception:
                    continue
            else:
                try:
                    v=int(part)
                    ports.append(v)
                except Exception:
                    continue
    ports = sorted(set(ports))
    print(f"{len(lines)} hedef dosyadan okunup taranıyor...")
    try:
        for host in lines:
            try:
                ip = socket.gethostbyname(host)
            except Exception as e:
                print(f"{host} çözümlenemedi: {e}")
                continue
            for p in ports:
                is_open, banner = scan_port(ip, p)
                if is_open:
                    print(f"[OPEN] {host}:{p}  {('Banner: ' + banner) if banner else ''}")
    except KeyboardInterrupt:
        print("\n[!] Dosyadan tarama durduruldu.")

# ----------------------------
# Menu
# ----------------------------
def show_menu() -> None:
    print("""
    ==============================
       Geliştirilmiş Menü Tabanlı Tarayıcı
    ==============================
    1) Tek port tara
    2) Port aralığı tara (tek host)
    3) Yaygın portları tara (tek host)
    4) IP aralığı veya CIDR tara (çoklu host)
    5) Hedefleri dosyadan tara
    6) Çık
    """)

def main() -> None:
    parser = argparse.ArgumentParser(description="Menu-based portable scanner (54society banner).")
    parser.add_argument("--color", choices=["green","red"], default="green",
                        help="Banner color for '54' (green or red). Default: green")
    args = parser.parse_args()

    # print banner
    print_banner(args.color)

    while True:
        show_menu()
        try:
            secim = input("Seçiminiz (1-6): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nÇıkılıyor...")
            break
        if secim == "1":
            single_port_scan()
        elif secim == "2":
            port_range_scan()
        elif secim == "3":
            hedef = input("Hedef IP/domain gir: ").strip()
            if hedef:
                try:
                    # reuse common_ports_scan but allow direct call that resolves host inside
                    ip = socket.gethostbyname(hedef)
                    print(f"{hedef} ({ip}) üzerinde yaygın portlar taranıyor...")
                    for p in COMMON_PORTS:
                        is_open, banner = scan_port(ip, p)
                        if is_open:
                            print(f"[OPEN] {p}  {('Banner: ' + banner) if banner else ''}")
                except Exception as e:
                    print(f"DNS çözümlenemedi: {e}")
        elif secim == "4":
            ip_range_scan()
        elif secim == "5":
            scan_from_file()
        elif secim == "6":
            print("Çıkılıyor...")
            break
        else:
            print("Geçersiz seçim. Lütfen 1-6 arası bir sayı girin.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nÇıkış (Ctrl+C)")
