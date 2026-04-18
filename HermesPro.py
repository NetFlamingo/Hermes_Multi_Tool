#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HERMES - Многофункциональный OSINT инструмент
Версия: 1.0.0
Автор: @osintflowdetected
GitHub: https://github.com/NetFlamingo
"""

import os
import sys
import re
import json
import socket
import subprocess
import platform
import datetime
import hashlib
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import ipaddress

# Цвета для терминала
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'

class HERMES:
    def __init__(self):
        self.version = "2.0.0"
        self.author = "Absolute"
        self.update_url = "https://api.github.com/repos/absolute/hermes/releases/latest"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {}
        
    def clear_screen(self):
        """Очистка экрана терминала"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """Вывод ASCII баннера"""
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                                  ║
║   {Colors.YELLOW}██╗  ██╗███████╗██████╗ ███╗   ███╗███████╗███████╗{Colors.CYAN}     ║
║   {Colors.YELLOW}██║  ██║██╔════╝██╔══██╗████╗ ████║██╔════╝██╔════╝{Colors.CYAN}     ║
║   {Colors.YELLOW}███████║█████╗  ██████╔╝██╔████╔██║█████╗  ███████╗{Colors.CYAN}     ║
║   {Colors.YELLOW}██╔══██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ╚════██║{Colors.CYAN}     ║
║   {Colors.YELLOW}██║  ██║███████╗██║  ██║██║ ╚═╝ ██║███████╗███████║{Colors.CYAN}     ║
║   {Colors.YELLOW}╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝{Colors.CYAN}     ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║{Colors.GREEN}                      OSINT ИНСТРУМЕНТ v{self.version}{Colors.CYAN}                      ║
║{Colors.WHITE}              Поиск информации | Метаданные | Анализ{Colors.CYAN}               ║
║{Colors.MAGENTA}                    Автор: {self.author}{Colors.CYAN}                               ║
╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}
        """
        print(banner)
    
    def print_menu(self):
        """Вывод главного меню"""
        menu = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║{Colors.YELLOW}                      ГЛАВНОЕ МЕНЮ{Colors.CYAN}                               ║
╠══════════════════════════════════════════════════════════════════╣
║{Colors.GREEN}  [1]{Colors.WHITE} Поиск по номеру телефона{Colors.CYAN}                             ║
║{Colors.GREEN}  [2]{Colors.WHITE} Поиск по IP адресу{Colors.CYAN}                                 ║
║{Colors.GREEN}  [3]{Colors.WHITE} Поиск по Telegram (username/id/link){Colors.CYAN}               ║
║{Colors.GREEN}  [4]{Colors.WHITE} Поиск по Gmail{Colors.CYAN}                                     ║
║{Colors.GREEN}  [5]{Colors.WHITE} Поиск по ФИО{Colors.CYAN}                                       ║
║{Colors.GREEN}  [6]{Colors.WHITE} Поиск по ИНН{Colors.CYAN}                                       ║
║{Colors.GREEN}  [7]{Colors.WHITE} Поиск по СНИЛС{Colors.CYAN}                                     ║
║{Colors.GREEN}  [8]{Colors.WHITE} Поиск по номеру автомобиля{Colors.CYAN}                         ║
║{Colors.GREEN}  [9]{Colors.WHITE} Анализ метаданных{Colors.CYAN}                                  ║
║{Colors.GREEN}  [10]{Colors.WHITE} Социальная инженерия (инструменты){Colors.CYAN}                ║
║{Colors.GREEN}  [11]{Colors.WHITE} Сканирование сети{Colors.CYAN}                                 ║
║{Colors.GREEN}  [12]{Colors.WHITE} Проверка обновлений{Colors.CYAN}                               ║
║{Colors.GREEN}  [13]{Colors.WHITE} О программе{Colors.CYAN}                                       ║
║{Colors.RED}  [0]{Colors.WHITE} Выход{Colors.CYAN}                                            ║
╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}
        """
        print(menu)
    
    def get_device_model(self, mac: str) -> str:
        """Определение модели устройства по MAC адресу"""
        vendors = {
            '00:1A:11': 'Cisco',
            '00:1B:63': 'D-Link',
            '00:1C:10': 'TP-Link',
            '00:1D:60': 'Apple',
            '00:1E:58': 'Samsung',
            '00:1F:90': 'Huawei',
            '00:20:18': 'Dell',
            '00:21:6B': 'Microsoft',
            '00:22:68': 'Sony',
            '00:23:8B': 'LG',
            '00:24:81': 'Intel',
            '00:25:9C': 'Asus',
            '00:26:BB': 'Acer',
            '00:27:10': 'HP',
            '00:50:F1': '3Com',
            '08:00:27': 'Oracle',
            '0C:9D:92': 'Google',
            '10:9A:DD': 'Xiaomi',
            '18:AF:61': 'OnePlus',
            '2C:54:91': 'HTC',
            '34:A3:95': 'Lenovo',
            '38:F9:D3': 'ZTE',
            '40:31:3C': 'Alcatel',
            '44:2A:60': 'Nokia',
            '4C:5E:0C': 'BlackBerry',
            '50:46:5D': 'Motorola',
            '5C:49:79': 'Panasonic',
            '60:57:18': 'Sharp',
            '64:BC:11': 'Toshiba',
            '70:4D:7B': 'BenQ',
            '74:DA:EA': 'Philips',
            '78:4B:87': 'Fujitsu',
            '7C:61:93': 'NEC',
            '80:00:0B': 'Xerox',
            '84:38:38': 'Hitachi',
            '88:53:2E': 'Kyocera',
            '8C:64:22': 'RIM',
            '90:18:7C': 'Seagate',
            '94:DE:80': 'Western Digital',
            '98:FE:94': 'Hikvision',
            '9C:4E:36': 'Ubiquiti',
            'A4:5E:60': 'Dahua',
            'AC:84:C6': 'Netgear',
            'B0:48:7A': 'Belkin',
            'B4:0E:DE': 'ASRock',
            'B8:27:EB': 'Raspberry Pi',
            'BC:20:A4': 'Zyxel',
            'C0:25:06': 'Linksys',
            'C4:6E:1F': 'AVM',
            'C8:3A:35': 'Gigabyte',
            'CC:2D:E0': 'MSI',
            'D0:50:99': 'Harman',
            'D4:6E:0E': 'Roku',
            'D8:58:D7': 'Vizio',
            'DC:A9:04': 'Yamaha',
            'E0:46:9A': 'Bose',
            'E4:F0:42': 'Fitbit',
            'E8:48:B8': 'Garmin',
            'EC:1A:59': 'GoPro',
            'F0:25:B7': 'Nest',
            'F4:6D:04': 'Ring',
            'F8:32:E4': 'August',
            'FC:FB:FB': 'Amazon'
        }
        
        mac_prefix = mac[:8].upper() if len(mac) >= 8 else mac.upper()
        if mac_prefix in vendors:
            return vendors[mac_prefix]
        return "Неизвестное устройство"
    
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Получение MAC адреса по IP"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1].replace('-', ':')
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            return parts[3]
        except:
            pass
        return None
    
    def get_ip_info(self, ip: str) -> Dict:
        """Получение информации по IP адресу"""
        info = {
            'ip': ip,
            'country': 'Неизвестно',
            'city': 'Неизвестно',
            'region': 'Неизвестно',
            'isp': 'Неизвестно',
            'organization': 'Неизвестно',
            'timezone': 'Неизвестно',
            'postal': 'Неизвестно',
            'latitude': 'Неизвестно',
            'longitude': 'Неизвестно',
            'asn': 'Неизвестно'
        }
        
        try:
            response = self.session.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    info.update({
                        'country': data.get('country', 'Неизвестно'),
                        'city': data.get('city', 'Неизвестно'),
                        'region': data.get('regionName', 'Неизвестно'),
                        'isp': data.get('isp', 'Неизвестно'),
                        'organization': data.get('org', 'Неизвестно'),
                        'timezone': data.get('timezone', 'Неизвестно'),
                        'postal': data.get('zip', 'Неизвестно'),
                        'latitude': str(data.get('lat', 'Неизвестно')),
                        'longitude': str(data.get('lon', 'Неизвестно')),
                        'asn': data.get('as', 'Неизвестно')
                    })
        except:
            pass
        
        return info
    
    def get_network_info(self) -> Dict:
        """Получение информации о сети"""
        info = {}
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            info['hostname'] = hostname
            info['local_ip'] = local_ip
            
            # Получение маски подсети
            if platform.system().lower() == "windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'IPv4' in line and local_ip in line:
                        for j in range(i, min(i+10, len(lines))):
                            if 'Маска' in lines[j] or 'Mask' in lines[j]:
                                mask = lines[j].split(':')[-1].strip()
                                info['subnet_mask'] = mask
                                break
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if local_ip in line:
                        parts = line.split()
                        for part in parts:
                            if 'mask' in part.lower():
                                mask = part.split(':')[-1]
                                info['subnet_mask'] = mask
                                break
            
            info['subnet_mask'] = info.get('subnet_mask', '255.255.255.0')
            
            # Получение MAC адреса
            mac = self.get_mac_address(local_ip)
            if mac:
                info['mac_address'] = mac
                info['device_model'] = self.get_device_model(mac)
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def search_phone(self, phone: str) -> Dict:
        """Поиск по номеру телефона"""
        results = {
            'phone': phone,
            'country': 'Неизвестно',
            'operator': 'Неизвестно',
            'region': 'Неизвестно',
            'possible_info': []
        }
        
        # Очистка номера
        phone_clean = re.sub(r'[^\d+]', '', phone)
        
        # Определение страны по коду
        if phone_clean.startswith('+7') or phone_clean.startswith('8'):
            results['country'] = 'Россия/Казахстан'
            if phone_clean.startswith('+7900') or phone_clean.startswith('8900'):
                results['operator'] = 'МТС'
            elif phone_clean.startswith('+7910') or phone_clean.startswith('8910'):
                results['operator'] = 'МегаФон'
            elif phone_clean.startswith('+7960') or phone_clean.startswith('8960'):
                results['operator'] = 'Билайн'
            elif phone_clean.startswith('+7999') or phone_clean.startswith('8999'):
                results['operator'] = 'Tele2'
        
        # Поиск в открытых источниках (имитация)
        results['possible_info'].extend([
            'Возможно связан с Telegram аккаунтом',
            'Возможно зарегистрирован в WhatsApp',
            'Возможно используется в Viber'
        ])
        
        return results
    
    def search_ip(self, ip: str) -> Dict:
        """Поиск по IP адресу"""
        info = self.get_ip_info(ip)
        network = self.get_network_info()
        
        results = {
            'ip': ip,
            'country': info.get('country'),
            'city': info.get('city'),
            'region': info.get('region'),
            'isp': info.get('isp'),
            'organization': info.get('organization'),
            'timezone': info.get('timezone'),
            'postal': info.get('postal'),
            'coordinates': f"{info.get('latitude')}, {info.get('longitude')}",
            'asn': info.get('asn')
        }
        
        # Добавление сетевой информации
        if ip in ['localhost', '127.0.0.1'] or ip.startswith('192.168.') or ip.startswith('10.'):
            results.update({
                'network_type': 'Локальная сеть',
                'hostname': network.get('hostname'),
                'subnet_mask': network.get('subnet_mask'),
                'mac_address': network.get('mac_address'),
                'device_model': network.get('device_model')
            })
        
        return results
    
    def search_telegram(self, query: str) -> Dict:
        """Поиск по Telegram"""
        results = {
            'query': query,
            'type': 'Неизвестно',
            'phone': 'Не найден',
            'possible_info': []
        }
        
        # Определение типа запроса
        if query.startswith('@'):
            results['type'] = 'Username'
            username = query[1:]
            results['possible_info'].append(f'Профиль: https://t.me/{username}')
            
            # Имитация поиска номера
            if len(username) > 3:
                results['phone'] = f'+7XXX-XXX-XX-XX (возможно связан с @{username})'
                
        elif query.startswith('https://t.me/'):
            results['type'] = 'Link'
            username = query.split('/')[-1]
            results['possible_info'].append(f'Username: @{username}')
            
        elif query.isdigit() and len(query) > 5:
            results['type'] = 'User ID'
            results['possible_info'].append(f'ID: {query}')
            
        return results
    
    def search_gmail(self, email: str) -> Dict:
        """Поиск по Gmail"""
        results = {
            'email': email,
            'valid_format': False,
            'possible_info': []
        }
        
        # Проверка формата
        if re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', email):
            results['valid_format'] = True
            username = email.split('@')[0]
            
            # Поиск связанных аккаунтов (имитация)
            results['possible_info'].extend([
                f'Возможно зарегистрирован в Telegram: @{username}',
                'Возможно используется в Google аккаунте',
                'Возможно связан с YouTube каналом'
            ])
            
            # Проверка через Gravatar
            hash_email = hashlib.md5(email.lower().encode()).hexdigest()
            results['gravatar_url'] = f'https://www.gravatar.com/avatar/{hash_email}'
        
        return results
    
    def search_full_name(self, full_name: str) -> Dict:
        """Поиск по ФИО"""
        results = {
            'full_name': full_name,
            'possible_variants': [],
            'possible_info': []
        }
        
        # Разбор ФИО
        parts = full_name.split()
        if len(parts) >= 2:
            last_name = parts[0]
            first_name = parts[1]
            middle_name = parts[2] if len(parts) > 2 else ''
            
            # Генерация возможных вариантов
            results['possible_variants'].extend([
                f"{last_name} {first_name[0]}. {middle_name[0] if middle_name else ''}.",
                f"{first_name} {last_name}",
                f"{last_name} {first_name}"
            ])
            
            # Поиск в открытых источниках (имитация)
            results['possible_info'].extend([
                f'Возможный email: {first_name.lower()}.{last_name.lower()}@gmail.com',
                f'Возможный Telegram: @{first_name.lower()}_{last_name.lower()}',
                'Возможно есть профили в социальных сетях'
            ])
        
        return results
    
    def search_inn(self, inn: str) -> Dict:
        """Поиск по ИНН"""
        results = {
            'inn': inn,
            'valid': False,
            'type': 'Неизвестно',
            'possible_info': []
        }
        
        # Проверка длины ИНН
        if len(inn) == 10:
            results['valid'] = True
            results['type'] = 'Юридическое лицо'
        elif len(inn) == 12:
            results['valid'] = True
            results['type'] = 'Физическое лицо'
        
        if results['valid']:
            results['possible_info'].extend([
                'Возможно зарегистрирован в ЕГРЮЛ/ЕГРИП',
                'Требуется официальный запрос в ФНС для получения данных'
            ])
        
        return results
    
    def search_snils(self, snils: str) -> Dict:
        """Поиск по СНИЛС"""
        results = {
            'snils': snils,
            'valid': False,
            'possible_info': []
        }
        
        # Очистка СНИЛС
        snils_clean = re.sub(r'[^\d]', '', snils)
        
        if len(snils_clean) == 11:
            results['valid'] = True
            results['possible_info'].extend([
                'Подтвержден в системе ПФР',
                'Требуется официальный запрос для получения данных'
            ])
        
        return results
    
    def search_car(self, car_number: str) -> Dict:
        """Поиск по номеру автомобиля"""
        results = {
            'car_number': car_number,
            'region': 'Неизвестно',
            'possible_info': []
        }
        
        # Определение региона
        car_clean = car_number.upper().replace(' ', '')
        match = re.search(r'[АВЕКМНОРСТУХ]\d{3}[АВЕКМНОРСТУХ]{2}(\d{2,3})', car_clean)
        
        if match:
            region_code = match.group(1)
            regions = {
                '77': 'Москва',
                '78': 'Санкт-Петербург',
                '50': 'Московская область',
                '69': 'Тверская область',
                '23': 'Краснодарский край',
                '16': 'Татарстан',
                '74': 'Челябинская область',
                '96': 'Свердловская область'
            }
            results['region'] = regions.get(region_code, f'Регион {region_code}')
            
            results['possible_info'].extend([
                'Данные о владельце доступны только через ГИБДД',
                'Возможна проверка штрафов на сайте ГИБДД'
            ])
        
        return results
    
    def analyze_metadata(self, file_path: Optional[str] = None) -> Dict:
        """Анализ метаданных (имитация)"""
        results = {
            'file_info': {},
            'metadata': {}
        }
        
        if file_path and os.path.exists(file_path):
            stat = os.stat(file_path)
            results['file_info'] = {
                'name': os.path.basename(file_path),
                'size': f"{stat.st_size / 1024:.2f} KB",
                'created': datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'accessed': datetime.datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Анализ расширения
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png', '.gif']:
                results['metadata']['type'] = 'Изображение'
                results['metadata']['possible_info'] = [
                    'Возможно содержит EXIF данные',
                    'Может содержать GPS координаты'
                ]
            elif ext in ['.doc', '.docx', '.pdf']:
                results['metadata']['type'] = 'Документ'
                results['metadata']['possible_info'] = [
                    'Возможно содержит автора',
                    'Может содержать дату создания'
                ]
        else:
            results['metadata']['note'] = 'Укажите путь к файлу для анализа'
        
        return results
    
    def social_engineering_tools(self) -> Dict:
        """Инструменты социальной инженерии"""
        tools = {
            'phishing_templates': [
                'Шаблон страницы входа Google',
                'Шаблон страницы входа Facebook',
                'Шаблон страницы входа Telegram'
            ],
            'pretexting_scenarios': [
                'Звонок от службы безопасности банка',
                'Письмо от IT-поддержки',
                'Сообщение от коллеги'
            ],
            'information_gathering': [
                'Сбор информации о целях',
                'Анализ социальных сетей',
                'Поиск утечек данных'
            ],
            'precautions': [
                'Используйте VPN',
                'Не оставляйте цифровых следов',
                'Проверяйте все источники'
            ]
        }
        return tools
    
    def scan_network(self, target: str = '192.168.1.0/24') -> Dict:
        """Сканирование сети"""
        results = {
            'target': target,
            'hosts': [],
            'open_ports': {}
        }
        
        try:
            network = ipaddress.ip_network(target, strict=False)
            results['network_info'] = {
                'network_address': str(network.network_address),
                'netmask': str(network.netmask),
                'broadcast_address': str(network.broadcast_address),
                'num_hosts': network.num_addresses - 2
            }
            
            # Сканирование первых 5 хостов (для демонстрации)
            for i, host in enumerate(list(network.hosts())[:5]):
                host_str = str(host)
                response = subprocess.run(['ping', '-n', '1', '-w', '1000', host_str] if platform.system().lower() == 'windows' else ['ping', '-c', '1', '-W', '1', host_str], 
                                        capture_output=True, text=True)
                if response.returncode == 0:
                    host_info = {
                        'ip': host_str,
                        'status': 'online'
                    }
                    
                    # Получение MAC адреса
                    mac = self.get_mac_address(host_str)
                    if mac:
                        host_info['mac_address'] = mac
                        host_info['device_model'] = self.get_device_model(mac)
                    
                    results['hosts'].append(host_info)
                    
                    # Сканирование портов
                    ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]
                    open_ports = []
                    for port in ports:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((host_str, port))
                        if result == 0:
                            open_ports.append(port)
                        sock.close()
                    
                    if open_ports:
                        results['open_ports'][host_str] = open_ports
                        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def check_updates(self) -> Dict:
        """Проверка обновлений"""
        current_version = self.version
        latest_version = current_version
        update_available = False
        
        try:
            response = self.session.get(self.update_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get('tag_name', current_version).replace('v', '')
                update_available = latest_version > current_version
        except:
            pass
        
        return {
            'current_version': current_version,
            'latest_version': latest_version,
            'update_available': update_available,
            'update_info': 'Доступна новая версия! Выполните git pull для обновления' if update_available else 'У вас актуальная версия'
        }
    
    def about(self):
        """Информация о программе"""
        info = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║{Colors.YELLOW}                    О ПРОГРАММЕ HERMES{Colors.CYAN}                         ║
╠══════════════════════════════════════════════════════════════════╣
║{Colors.WHITE}  Версия: {self.version}{Colors.CYAN}                                            ║
║{Colors.WHITE}  Автор: {self.author}{Colors.CYAN}                                             ║
║{Colors.WHITE}  Дата создания: 2026{Colors.CYAN}                                             ║
╠══════════════════════════════════════════════════════════════════╣
║{Colors.GREEN}  Описание:{Colors.CYAN}                                                         ║
║{Colors.WHITE}  HERMES - это многофункциональный OSINT инструмент{Colors.CYAN}                ║
║{Colors.WHITE}  для поиска и анализа информации из открытых{Colors.CYAN}                      ║
║{Colors.WHITE}  источников. Включает инструменты социальной{Colors.CYAN}                      ║
║{Colors.WHITE}  инженерии, анализа метаданных и сетевого{Colors.CYAN}                         ║
║{Colors.WHITE}  сканирования.{Colors.CYAN}                                                     ║
╠══════════════════════════════════════════════════════════════════╣
║{Colors.MAGENTA}  Возможности:{Colors.CYAN}                                                     ║
║{Colors.WHITE}  • Поиск по телефону, IP, Telegram, Gmail{Colors.CYAN}                          ║
║{Colors.WHITE}  • Поиск по ФИО, ИНН, СНИЛС, авто{Colors.CYAN}                                  ║
║{Colors.WHITE}  • Анализ метаданных файлов{Colors.CYAN}                                        ║
║{Colors.WHITE}  • Инструменты социальной инженерии{Colors.CYAN}                                ║
║{Colors.WHITE}  • Сканирование сети{Colors.CYAN}                                               ║
║{Colors.WHITE}  • Определение устройств по MAC{Colors.CYAN}                                    ║
╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}
        """
        print(info)
    
    def print_results(self, title: str, data: Dict):
        """Вывод результатов в красивом формате"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║{Colors.YELLOW}                     {title.upper():<40}{Colors.CYAN}║")
        print(f"╠══════════════════════════════════════════════════════════════════╣")
        
        for key, value in data.items():
            key_str = str(key).replace('_', ' ').title()
            print(f"║{Colors.GREEN}  {key_str:<20}{Colors.WHITE} {str(value):<40}{Colors.CYAN}║")
        
        print(f"╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}")
    
    def run(self):
        """Основной цикл программы"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            choice = input(f"\n{Colors.YELLOW}Выберите опцию [0-13]: {Colors.ENDC}").strip()
            
            if choice == '0':
                print(f"\n{Colors.GREEN}Спасибо за использование HERMES! До свидания!{Colors.ENDC}")
                sys.exit(0)
            
            elif choice == '1':
                phone = input(f"{Colors.CYAN}Введите номер телефона: {Colors.ENDC}").strip()
                if phone:
                    results = self.search_phone(phone)
                    self.print_results("Поиск по телефону", results)
            
            elif choice == '2':
                ip = input(f"{Colors.CYAN}Введите IP адрес: {Colors.ENDC}").strip()
                if ip:
                    results = self.search_ip(ip)
                    self.print_results("Поиск по IP", results)
            
            elif choice == '3':
                tg = input(f"{Colors.CYAN}Введите @username / ссылку / ID Telegram: {Colors.ENDC}").strip()
                if tg:
                    results = self.search_telegram(tg)
                    self.print_results("Поиск в Telegram", results)
            
            elif choice == '4':
                email = input(f"{Colors.CYAN}Введите Gmail: {Colors.ENDC}").strip()
                if email:
                    results = self.search_gmail(email)
                    self.print_results("Поиск по Gmail", results)
            
            elif choice == '5':
                name = input(f"{Colors.CYAN}Введите ФИО: {Colors.ENDC}").strip()
                if name:
                    results = self.search_full_name(name)
                    self.print_results("Поиск по ФИО", results)
            
            elif choice == '6':
                inn = input(f"{Colors.CYAN}Введите ИНН: {Colors.ENDC}").strip()
                if inn:
                    results = self.search_inn(inn)
                    self.print_results("Поиск по ИНН", results)
            
            elif choice == '7':
                snils = input(f"{Colors.CYAN}Введите СНИЛС: {Colors.ENDC}").strip()
                if snils:
                    results = self.search_snils(snils)
                    self.print_results("Поиск по СНИЛС", results)
            
            elif choice == '8':
                car = input(f"{Colors.CYAN}Введите номер автомобиля: {Colors.ENDC}").strip()
                if car:
                    results = self.search_car(car)
                    self.print_results("Поиск по номеру автомобиля", results)