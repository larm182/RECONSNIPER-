import json
import requests
import phonenumbers
from ipwhois import IPWhois
from rich import print
from rich.panel import Panel
from rich.live import Live
from socket import gethostbyaddr, socket, AF_INET, SOCK_STREAM
from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
from time import sleep


ascii_logo = r"""
    ██████╗ ██╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║   ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗████╗ ████║
    ██████╔╝██║   ██║█████╗  ██║     ██║   ██║██████╔╝██╔████╔██║
    ██╔═══╝ ██║   ██║██╔══╝  ██║     ██║   ██║██╔═══╝ ██║╚██╔╝██║
    ██║     ╚██████╔╝███████╗╚██████╗╚██████╔╝██║     ██║ ╚═╝ ██║
    ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝
        [bold green]powered by Luis Ángel Ramirez Mendoza • RECONSNIPER
        OSINT Tactical Unit • Cyber Intelligence ⚔[/bold green]
"""

def animacion(texto, pasos=10, delay=0.2):
    with Live("", refresh_per_second=10) as live:
        for i in range(1, pasos+1):
            live.update(f"[bold yellow]{texto}[/] {'█' * i}")
            sleep(delay)

def geolocate_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        return {
            "IP": ip,
            "País": response.get("country"),
            "Ciudad": response.get("city"),
            "Región": response.get("regionName"),
            "ISP": response.get("isp"),
            "Org": response.get("org"),
            "Latitud": response.get("lat"),
            "Longitud": response.get("lon"),
        }
    except:
        return {"error": "Error al geolocalizar IP"}

def whois_ip(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return {
            "ASN": result.get("asn"),
            "CIDR": result.get("network", {}).get("cidr"),
            "Nombre de Org": result.get("network", {}).get("name"),
            "Contacto": result.get("objects", {}),
        }
    except:
        return {"error": "Error en WHOIS"}

def reverse_dns(ip):
    try:
        host = gethostbyaddr(ip)
        return host[0]
    except:
        return "No resuelto"

def scan_ports(ip, ports=[21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]):
    open_ports = []
    for port in ports:
        try:
            with socket(AF_INET, SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except:
            continue
    return {"Puertos abiertos": ", ".join(map(str, open_ports)) if open_ports else "Ninguno detectado"}

def detect_technologies(ip):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(f"http://{ip}", headers=headers, timeout=5)
        techs = []
        server = response.headers.get("Server")
        powered = response.headers.get("X-Powered-By")
        if server: techs.append(f"Servidor: {server}")
        if powered: techs.append(f"X-Powered-By: {powered}")
        return {"Tecnologías detectadas": ", ".join(techs) if techs else "No detectado"}
    except:
        return {"Tecnologías detectadas": "No se pudo detectar"}

def check_blacklists(ip):
    blacklisted_ips = ["123.45.67.89", "8.8.8.8"]
    return {"En lista negra": "Sí" if ip in blacklisted_ips else "No"}

def analyze_phone(phone):
    try:
        number = phonenumbers.parse(phone, None)
        if not phonenumbers.is_valid_number(number):
            return {"error": "Número no válido"}
        
        tipo = number_type(number)
        tipo_str = {
            PhoneNumberType.MOBILE: "Móvil",
            PhoneNumberType.FIXED_LINE: "Línea fija",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fijo o móvil",
            PhoneNumberType.VOIP: "VOIP",
        }.get(tipo, "Desconocido")

        return {
            "Número": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "Región": geocoder.description_for_number(number, "es"),
            "Operador": carrier.name_for_number(number, "es"),
            "Tipo": tipo_str,
            "Válido": "Sí" if phonenumbers.is_valid_number(number) else "No",
        }
    except:
        return {"error": "No se pudo analizar el número"}

def print_results(title, data):
    formatted = "\n".join([f"[bold cyan]{k}[/]: {v}" for k, v in data.items()])
    print(Panel(formatted, title=title, expand=False))

def generar_buscadores(numero):
    queries = {
        "Google": f"https://www.google.com/search?q=\"{numero}\" site:pastebin.com OR site:facebook.com OR site:x.com",
        "Spamcalls.net": f"https://spamcalls.net/en/number/{numero}",
        "Should I Answer": f"https://www.shouldianswer.com/phone-number/{numero}"
    }
    return queries


def export_results(nombre_archivo, datos):
    with open(f"reporte_{nombre_archivo}.txt", "w", encoding="utf-8") as f:
        for seccion, contenido in datos.items():
            f.write(f"=== {seccion.upper()} ===\n")
            for k, v in contenido.items():
                f.write(f"{k}: {v}\n")
            f.write("\n")
    with open(f"reporte_{nombre_archivo}.json", "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=4, ensure_ascii=False)
    print(f"\n[green]✅ Reportes guardados como:[/]\n📄 reporte_{nombre_archivo}.txt\n📦 reporte_{nombre_archivo}.json")

def main():
    print(f"[bold cyan]{ascii_logo}[/]\n")
    print("[bold green]--- RECONSNIPER ---[/]")
    print("[bold magenta]1.[/] Analizar dirección IP")
    print("[bold magenta]2.[/] Analizar número de teléfono")
    print("[bold magenta]3.[/] Salir")

    opcion = input("\nSelecciona una opción: ")

    if opcion == "1":
        ip = input("🔍 Ingresa la dirección IP a analizar: ")
        animacion("Escaneando IP...", 12)

        geo = geolocate_ip(ip)
        whois = whois_ip(ip)
        reverse = reverse_dns(ip)
        puertos = scan_ports(ip)
        tech = detect_technologies(ip)
        blacklist = check_blacklists(ip)

        print_results("🌍 Geolocalización", geo)
        print_results("📄 WHOIS", whois)
        print_results("🔁 DNS Inverso", {"DNS Inverso": reverse})
        print_results("🛠 Puertos Abiertos", puertos)
        print_results("🧠 Tecnologías", tech)
        print_results("🛑 Blacklist", blacklist)

        guardar = input("\n¿Deseas guardar el informe? (s/n): ").lower()
        if guardar == "s":
            export_results(ip.replace(".", "_"), {
                "Geolocalización": geo,
                "WHOIS": whois,
                "DNS Inverso": {"DNS Inverso": reverse},
                "Puertos Abiertos": puertos,
                "Tecnologías": tech,
                "Blacklist": blacklist
            })

    elif opcion == "2":
        numero = input("📱 Ingresa el número de teléfono (con código internacional, ej: +573001234567): ")
        animacion("Analizando número...", 10)
        telefono = analyze_phone(numero)
        print_results("📞 Información del número", telefono)

        buscadores = generar_buscadores(numero)
        print_results("🌐 Búsqueda en línea", buscadores)

        guardar = input("\n¿Deseas guardar el informe? (s/n): ").lower()
        if guardar == "s":
            export_results(numero.replace("+", ""), {"Número de Teléfono": telefono})

    elif opcion == "3":
        print("[bold red]Saliendo...[/]")
        exit()
    else:
        print("[bold red]Opción no válida.[/]")

if __name__ == "__main__":
    main()
