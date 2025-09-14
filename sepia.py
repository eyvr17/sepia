import os
import sys
import subprocess
import platform
import socket
import time
import webbrowser
import requests
import threading

# Instalador pip para librerías externas
def install(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except Exception as e:
        print(f"Error instalando {package}: {e}")

# Verifica si el script corre como administrador (Windows)
def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Ejecuta un comando, devolviendo stdout
def run_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        return e.output

# Descarga e instala Nmap automáticamente para Windows si no está instalado
def ensure_nmap():
    nmap_path = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
    if not os.path.exists(nmap_path):
        print("[*] Nmap no está instalado. Instalando automáticamente...")
        url = "https://nmap.org/dist/nmap-7.93-setup.exe"
        installer = "nmap-setup.exe"
        try:
            import urllib.request
            urllib.request.urlretrieve(url, installer)
            print("[*] Ejecutando instalador de Nmap...")
            subprocess.run([installer, "/S"], check=True)
            os.remove(installer)
            print("[*] Nmap instalado correctamente.")
        except Exception as e:
            print(f"[ERROR] Falló la instalación automática de Nmap: {e}")
            print("Por favor instala Nmap manualmente desde https://nmap.org/download.html")
            sys.exit(1)
    else:
        print("[*] Nmap detectado.")

# Geolocalización de IP usando ipinfo.io API
def geolocate():
    ip = input("Introduce la IP: ").strip()
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        data = response.json()
        print("\n--- Información de Geolocalización ---")
        for k,v in data.items():
            print(f"{k.capitalize()}: {v}")
    except Exception as e:
        print(f"Error al obtener geolocalización: {e}")
    input("\nPresiona Enter para volver al menú...")

# Resolver DNS (A, MX, NS)
def tracedns():
    import dns.resolver
    target = input("Introduce dominio o IP: ").strip()
    tipos = ["A", "MX", "NS"]
    for t in tipos:
        try:
            answers = dns.resolver.resolve(target, t)
            print(f"\nRegistros {t}:")
            for rdata in answers:
                print(f" - {rdata.to_text()}")
        except Exception as e:
            print(f"No se encontraron registros {t} o error: {e}")
    input("\nPresiona Enter para volver al menú...")

# Escaneo de puertos usando socket (rápido pero básico)
def portscan():
    ip = input("IP objetivo: ").strip()
    ports_raw = input("Puertos (ej. 22,80,443): ").strip()
    ports = []
    try:
        for part in ports_raw.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end)+1))
            else:
                ports.append(int(part))
    except:
        print("Formato de puertos incorrecto.")
        input("Enter para continuar...")
        return

    print(f"\nEscaneando {ip} en puertos {ports} ...")
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Puerto {port} -> ABIERTO")
            open_ports.append(port)
        sock.close()
    if not open_ports:
        print("No se encontraron puertos abiertos.")
    input("\nPresiona Enter para volver al menú...")

# Escaneo avanzado con Nmap (requiere que esté instalado)
def nmap_scan():
    ensure_nmap()
    ip = input("IP objetivo: ").strip()
    options = input("Opciones Nmap (ejemplo: -sS -p 1-1000): ").strip()
    nmap_path = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
    if not os.path.exists(nmap_path):
        print("[ERROR] Nmap no encontrado. Instalalo y vuelve a intentarlo.")
        input("Enter para continuar...")
        return
    print(f"\nEjecutando: nmap {options} {ip}")
    try:
        subprocess.run([nmap_path] + options.split() + [ip])
    except Exception as e:
        print(f"Error ejecutando nmap: {e}")
    input("\nPresiona Enter para volver al menú...")

# Abrir sitios web de DDoS (para pruebas, con precaución legal)
def ddos():
    urls = [
        "https://freestresser.so/",
        "https://hardstresser.com/",
        "https://stresser.net/",
        "https://str3ssed.co/",
        "https://projectdeltastress.com/"
    ]
    print("\nEnlaces para pruebas de DDoS (sólo para aprendizaje y pruebas controladas):")
    for i, url in enumerate(urls, 1):
        print(f"{i}. {url}")
    choice = input("Selecciona un número para abrir o Enter para volver: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(urls):
        webbrowser.open(urls[int(choice) - 1])

# Obtener MAC de IP local (Windows)
def macaddr():
    ip = input("Introduce IP de la red local: ").strip()
    print(f"\nBuscando dirección MAC para IP {ip} ...")
    try:
        output = run_command(f"arp -a {ip}")
        print(output)
    except Exception as e:
        print(f"Error ejecutando arp: {e}")
    input("\nPresiona Enter para volver al menú...")

# Escaneo rápido de red local con ping sweep (requiere privilegios)
def ping_sweep():
    subnet = input("Introduce el rango de IP (ej: 192.168.1): ").strip()
    print(f"\nHaciendo ping sweep en {subnet}.0/24 ...")
    alive = []

    def ping(ip):
        ret = os.system(f"ping -n 1 -w 1000 {ip} >nul 2>&1")
        if ret == 0:
            alive.append(ip)
            print(f"{ip} está activo")

    threads = []
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        t = threading.Thread(target=ping, args=(ip,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print(f"\nIPs activas: {alive}")
    input("\nPresiona Enter para volver al menú...")

# Submenú OSINT con herramientas básicas
def submenu_osint():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=== Menú OSINT ===")
        print("1. Geolocalizar IP")
        print("2. Consultar DNS")
        print("3. Buscar en VirusTotal (requiere API)")
        print("4. Volver")
        choice = input("Elige una opción: ").strip()
        if choice == '1':
            geolocate()
        elif choice == '2':
            tracedns()
        elif choice == '3':
            virustotal_query()
        elif choice == '4':
            break
        else:
            print("Opción inválida.")

# Función ejemplo de consulta VirusTotal (requiere API key)
def virustotal_query():
    api_key = input("Introduce tu API key de VirusTotal: ").strip()
    domain = input("Introduce dominio o IP a consultar: ").strip()
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print(data)
        else:
            print(f"Error en consulta VirusTotal: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")
    input("Presiona Enter para volver...")

# Submenú Wi-Fi (requiere herramientas adicionales)
def submenu_wifi():
    print("\nOpciones Wi-Fi no implementadas aún (requiere herramientas especiales).\n")
    input("Presiona Enter para volver al menú principal...")

# Advertencia legal
def legal_warning():
    print("""
[!] Recuerda que esta herramienta es para uso educativo y pruebas en entornos controlados.
El uso indebido de estas herramientas puede ser ilegal y conllevar consecuencias.
Responsabilidad del usuario.
""")
    time.sleep(3)

# Menú principal
def main_menu():
    if not is_admin():
        print("[ERROR] Este script debe ejecutarse como administrador en Windows.")
        input("Presiona Enter para salir...")
        sys.exit(1)

    legal_warning()

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("========================================")
        print("           Crazy Sepia Tool v1.0")
        print("        X.com: https://x.com/eyvr17")
        print("========================================")
        print("[1] Geolocalizar IP")
        print("[2] Consultar DNS")
        print("[3] Escaneo de puertos rápido (socket)")
        print("[4] Escaneo avanzado con Nmap")
        print("[5] Mostrar enlaces DDoS (solo para estudio)")
        print("[6] Obtener MAC de IP en red local")
        print("[7] Ping sweep en red local")
        print("[8] Menú OSINT")
        print("[9] Menú Wi-Fi (pendiente)")
        print("[0] Salir")
        choice = input("\nSelecciona una opción: ").strip()

        if choice == '1':
            geolocate()
        elif choice == '2':
            tracedns()
        elif choice == '3':
            portscan()
        elif choice == '4':
            nmap_scan()
        elif choice == '5':
            ddos()
        elif choice == '6':
            macaddr()
        elif choice == '7':
            ping_sweep()
        elif choice == '8':
            submenu_osint()
        elif choice == '9':
            submenu_wifi()
        elif choice == '0':
            print("Saliendo... Gracias por usar Crazy Sepia Tool.")
            sys.exit(0)
        else:
            print("Opción no válida.")
            time.sleep(2)

if __name__ == "__main__":
    # Instalamos las librerías necesarias antes de arrancar
    required_packages = ['requests', 'dnspython']
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            print(f"Instalando paquete requerido: {pkg}")
            install(pkg)

    main_menu()

