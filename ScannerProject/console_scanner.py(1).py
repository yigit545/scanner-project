#!/usr/bin/env python3
"""
scanner_console.py

Geliştirilmiş komut kabuğu (REPL) tarayıcı — IP aralığı ve hedef dosyası desteği ile.
FSociety banner ile başlar: "54society"
"""

import cmd, socket, concurrent.futures, csv, time, ipaddress

# --------------------
# BANNER
# --------------------
def show_banner():
    GREEN = "\033[32m"
    RED   = "\033[31m"
    RESET = "\033[0m"

    logo = f"""
{GREEN}54{RESET}society       _____ ____   ____  _____
{GREEN}54{RESET}society      |  ___|  _ \\ / ___|| ____|
{GREEN}54{RESET}society      | |_  | | | | |  _ |  _|
{GREEN}54{RESET}society      |  _| | |_| | |_| || |___
{GREEN}54{RESET}society      |_|   |____/ \\____||_____|
"""
    print(logo)

# --------------------
# PORT & TARGET UTILS
# --------------------
def parse_ports(s):
    s = (s or "").replace(" ", "")
    parts = s.split(",")
    ports = set()
    for p in parts:
        if not p: continue
        if "-" in p:
            try:
                a,b = p.split("-", 1)
                a=int(a); b=int(b)
                if a>b: a,b = b,a
                a=max(1,a); b=min(65535,b)
                ports.update(range(a,b+1))
            except ValueError: continue
        else:
            try:
                val=int(p)
                if 1<=val<=65535: ports.add(val)
            except ValueError: continue
    return sorted(ports)

def expand_targets(spec):
    spec=(spec or "").strip()
    if not spec: return []
    # CIDR
    try:
        if '/' in spec:
            net = ipaddress.ip_network(spec, strict=False)
            return [str(ip) for ip in net.hosts()]
    except Exception: pass
    # RANGE
    if '-' in spec and not any(c.isalpha() for c in spec):
        try:
            a,b = spec.split('-',1)
            start = ipaddress.IPv4Address(a.strip())
            end = ipaddress.IPv4Address(b.strip())
            if int(start)>int(end): start,end=end,start
            alist=[]
            cur=int(start)
            while cur<=int(end):
                alist.append(str(ipaddress.IPv4Address(cur)))
                cur+=1
            return alist
        except Exception: return []
    # single host
    return [spec]

def check_port(host_ip, port, timeout=1.0):
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res=sock.connect_ex((host_ip,port))
        if res==0:
            try:
                sock.settimeout(0.6)
                sock.sendall(b"\n")
                banner=sock.recv(1024).decode(errors="ignore").strip()
            except: banner=""
            sock.close()
            return True,banner
        sock.close()
        return False,""
    except Exception as e: return False,str(e)

# --------------------
# SCANNER SHELL
# --------------------
class ScannerShell(cmd.Cmd):
    intro="Geliştirilmiş scanner kabuğuna hoşgeldin. Yardım için 'help' yaz.\n"
    prompt="scanner> "

    def __init__(self):
        super().__init__()
        self.target=None
        self.target_ip=None
        self.targets=[]
        self.ports=[80,443]
        self.timeout=1.0
        self.max_workers=50
        self.results={}
        self.last_run=None

    # ... (set, setrange, setfile, ports, timeout, workers metotları buraya) ...

    def _scan_host(self,host):
        try: ip=socket.gethostbyname(host)
        except Exception as e:
            print(f"{host} çözümlenemedi: {e}")
            return
        for p in self.ports:
            is_open,banner=check_port(ip,p,self.timeout)
            self.results[(host,p)] = (is_open,banner)
            if is_open:
                print(f"[OPEN] {host}:{p}  {('Banner: '+banner) if banner else ''}")

    def do_scan(self,arg):
        if not self.targets:
            print("Önce hedef ayarlayın.")
            return
        if not self.ports:
            print("Port listesi boş.")
            return
        print(f"Toplam hedef: {len(self.targets)}  Port sayısı: {len(self.ports)}")
        self.results.clear()
        start=time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers,len(self.targets))) as exe:
            futures=[exe.submit(self._scan_host,h) for h in self.targets]
            try:
                for fut in concurrent.futures.as_completed(futures): pass
            except KeyboardInterrupt:
                print("\n[!] Tarama durduruldu")
        elapsed=time.time()-start
        self.last_run=time.ctime()
        print(f"\nTarama tamamlandı. Süre: {elapsed:.2f}s  ({self.last_run})")

    def do_exit(self,arg): print("Çıkılıyor..."); return True
    def do_quit(self,arg): return self.do_exit(arg)
    def emptyline(self): pass
    def do_EOF(self,arg): print("\n(EoF) Çıkılıyor..."); return True

if __name__=='__main__':
    show_banner()
    ScannerShell().cmdloop()
