import smtplib
import socket
import dns.resolver
import whois
import json
import requests
import re
from typing import Dict, List, Any

PHONE_API_KEY = "a077fc9b09464116b9623401175cb742"
PHONE_API_URL = f"https://phonevalidation.abstractapi.com/v1/"

def display_banner():
    print("=" * 50)
    print("           Validator Tool")
    print("=" * 50)
    print("[ Создатель и кодер: @osintapolov ] {validator tool}")
    print()

def display_menu():
    print("1. Email Validator")
    print("2. Phone Validator") 
    print("3. Search domain")
    print()

def validate_email_format(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def get_mx_records(domain: str) -> List[str]:
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(mx.exchange).rstrip('.') for mx in sorted(mx_records, key=lambda x: x.preference)]
    except:
        return []

def smtp_validation(email: str) -> Dict[str, Any]:
    result = {
        "email": email,
        "valid_format": validate_email_format(email),
        "mx_records": [],
        "steps": [],
        "final_status": "invalid",
        "smtp_code": None
    }
    
    if not result["valid_format"]:
        return result
    
    domain = email.split('@')[1]
    mx_records = get_mx_records(domain)
    result["mx_records"] = mx_records
    
    if not mx_records:
        return result
    
    for mx in mx_records:
        try:
            server = smtplib.SMTP(mx, timeout=10)
            connect_code, connect_msg = server.connect(mx)
            result["steps"].append({
                "connect": {
                    "mx": mx,
                    "code": connect_code,
                    "msg": connect_msg.decode() if isinstance(connect_msg, bytes) else str(connect_msg)
                }
            })
            
            helo_code, helo_msg = server.helo()
            result["steps"].append({
                "helo": {
                    "code": helo_code,
                    "msg": helo_msg.decode() if isinstance(helo_msg, bytes) else str(helo_msg)
                }
            })
            
            mail_from_code, mail_from_msg = server.mail('test@example.com')
            result["steps"].append({
                "mail_from": {
                    "code": mail_from_code,
                    "msg": mail_from_msg.decode() if isinstance(mail_from_msg, bytes) else str(mail_from_msg)
                }
            })
            
            rcpt_to_code, rcpt_to_msg = server.rcpt(email)
            result["steps"].append({
                "rcpt_to": {
                    "email": email,
                    "code": rcpt_to_code,
                    "msg": rcpt_to_msg.decode() if isinstance(rcpt_to_msg, bytes) else str(rcpt_to_msg)
                }
            })
            
            quit_code, quit_msg = server.quit()
            result["steps"].append({
                "quit": {
                    "code": quit_code,
                    "msg": quit_msg.decode() if isinstance(quit_msg, bytes) else str(quit_msg)
                }
            })
            
            result["final_status"] = "valid" if rcpt_to_code == 250 else "invalid"
            result["smtp_code"] = rcpt_to_code
            break
            
        except Exception as e:
            continue
    
    return result

def phone_validation(phone: str) -> Dict[str, Any]:
    params = {
        'api_key': PHONE_API_KEY,
        'phone': phone
    }
    
    try:
        response = requests.get(PHONE_API_URL, params=params)
        data = response.json()
        
        result = {
            "valid": data.get('valid', False),
            "international_format": data.get('international_format', ''),
            "local_format": data.get('local_format', ''),
            "country_code": data.get('country', {}).get('code', ''),
            "country_name": data.get('country', {}).get('name', ''),
            "location": data.get('location', ''),
            "carrier": data.get('carrier', ''),
            "type": data.get('type', '')
        }
        
        return result
    except Exception as e:
        return {
            "valid": False,
            "international_format": "",
            "local_format": "",
            "country_code": "",
            "country_name": "",
            "location": "",
            "carrier": "",
            "type": f"Error: {str(e)}"
        }

def scan_ports(ip: str, ports: List[int] = None) -> List[int]:
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389, 5432, 8080, 8443]
    
    open_ports = []
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                open_ports.append(port)
        except:
            pass
    
    return open_ports

def domain_search(domain: str) -> Dict[str, Any]:
    result = {
        "domain": domain,
        "ip_address": "",
        "open_ports": [],
        "whois_info": {},
        "dns_records": {}
    }
    
    try:
        ip = socket.gethostbyname(domain)
        result["ip_address"] = ip
        
        result["open_ports"] = scan_ports(ip)
        
        try:
            whois_info = whois.whois(domain)
            result["whois_info"] = {
                "registrar": whois_info.registrar,
                "creation_date": str(whois_info.creation_date),
                "expiration_date": str(whois_info.expiration_date),
                "name_servers": whois_info.name_servers
            }
        except:
            result["whois_info"] = {"error": "WHOIS lookup failed"}
        
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            result["dns_records"]["A"] = [str(record) for record in a_records]
        except:
            result["dns_records"]["A"] = []
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result["dns_records"]["MX"] = [str(record.exchange) for record in mx_records]
        except:
            result["dns_records"]["MX"] = []
            
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            result["dns_records"]["NS"] = [str(record) for record in ns_records]
        except:
            result["dns_records"]["NS"] = []
            
    except Exception as e:
        result["error"] = str(e)
    
    return result

def main():
    while True:
        display_banner()
        display_menu()
        
        choice = input("> Выберите функцию: ").strip()
        
        if choice == "1":
            email = input("> Отправьте email адрес: ").strip()
            print("\nРезультаты SMTP запроса:")
            result = smtp_validation(email)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
            input("\n> Нажмите на Enter чтобы вернуться в меню…")
            
        elif choice == "2":
            phone = input("> Отправьте номер телефона: ").strip()
            print("\nРезультаты проверки телефона:")
            result = phone_validation(phone)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
            input("\n> Нажмите на Enter чтобы вернуться в меню…")
            
        elif choice == "3":
            domain = input("> Отправьте домен: ").strip()
            print("\nРезультаты поиска домена:")
            result = domain_search(domain)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
            input("\n> Нажмите на Enter чтобы вернуться в меню…")
            
        else:
            print("Неверный выбор. Попробуйте снова.")
            input("\n> Нажмите на Enter чтобы продолжить…")

if __name__ == "__main__":
    main()
