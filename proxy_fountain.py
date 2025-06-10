#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =============================================================================
#   Proxy-Fountain: A simple, lightweight, and intelligent proxy provider.
#   License: MIT
# =============================================================================

import json
import logging
import logging.handlers
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

try:
    import requests
    import yaml
except ImportError:
    print("Ошибка: Необходимые библиотеки не найдены.")
    print("Пожалуйста, выполните команду: pip install -r requirements.txt")
    exit(1)

# --- Глобальные переменные и утилиты ---
CONFIG_FILE = 'config.yaml'
PROXIES = set()
CONFIG = {}
proxies_lock = threading.Lock()
config_lock = threading.Lock()
PROXY_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})")


def parse_time_interval(value, default):
    """Безопасно вычисляет временной интервал из строки или числа."""
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            result = eval(value, {"__builtins__": {}}, {})
            if isinstance(result, (int, float)):
                return result
            logging.warning(
                f"Выражение '{value}' не является числом. Используется значение по умолчанию: {default}")
        except Exception as e:
            logging.warning(
                f"Не удалось вычислить интервал '{value}': {e}. Используется значение по умолчанию: {default}")
    return default


def setup_logging(config):
    """Настраивает систему логирования с ротацией файлов."""
    log_config = config.get('logging', {})
    log_file = log_config.get('log_file', 'proxy_fountain.log')
    console_level = getattr(logging, log_config.get(
        'log_level_console', 'INFO').upper(), logging.INFO)
    file_level = getattr(logging, log_config.get(
        'log_level_file', 'DEBUG').upper(), logging.DEBUG)

    logger = logging.getLogger()
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

    fh = logging.handlers.TimedRotatingFileHandler(
        log_file, when='D', interval=1, backupCount=7, encoding='utf-8')
    fh.setLevel(file_level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(console_level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)


def load_and_update_config():
    """Читает конфиг с диска и безопасно обновляет глобальную переменную."""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            new_config_data = yaml.safe_load(f)
            with config_lock:
                global CONFIG
                CONFIG = new_config_data
            return True
    except (FileNotFoundError, yaml.YAMLError) as e:
        logging.error(
            f"Не удалось загрузить или распарсить {CONFIG_FILE}: {e}")
        return False


def update_proxies(config):
    """Обновляет список прокси, используя предоставленную конфигурацию."""
    logging.info("Начало полного обновления списка прокси...")
    new_proxies = set()
    for source in config.get('sources', []):
        if not source.get('enabled', False):
            continue
        url, proxy_type = source.get('url'), source.get('type', 'http')
        if not url:
            continue
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()
            found_count = 0
            for line in lines:
                match = PROXY_PATTERN.search(line)
                if match:
                    new_proxies.add(f"{proxy_type}://{match.group(1)}")
                    found_count += 1
            logging.info(
                f"  - ({proxy_type.upper()}) Найдено: {found_count} из {url}")
        except requests.RequestException as e:
            logging.error(f"  - Не удалось получить данные с {url}: {e}")

    with proxies_lock:
        global PROXIES
        PROXIES = new_proxies
    logging.info(
        f"Обновление завершено. Всего уникальных прокси: {len(PROXIES)}")


def background_updater_task():
    """Умный планировщик, который отслеживает индивидуальные таймеры."""
    threading.current_thread().name = "Updater"
    source_schedules = {}
    config_reload_timer = time.time() + 60

    with config_lock:
        current_config = CONFIG.copy()

    default_interval = parse_time_interval(
        current_config.get('default_update_interval_seconds'), 3600)

    for source in current_config.get('sources', []):
        if source.get('enabled', False) and source.get('url'):
            interval = parse_time_interval(source.get(
                'update_interval_seconds'), default_interval)
            source_schedules[source.get('url')] = time.time() + interval
    logging.debug(
        "Планировщик инициализирован. Первоначальное расписание установлено.")

    while True:
        now = time.time()

        if now >= config_reload_timer:
            if load_and_update_config():
                logging.debug("Файл конфигурации успешно перезагружен.")
            config_reload_timer = now + 60

        with config_lock:
            current_config = CONFIG.copy()

        default_interval = parse_time_interval(
            current_config.get('default_update_interval_seconds'), 3600)

        needs_full_update = False
        trigger_source = None

        for source_url, next_update_time in list(source_schedules.items()):
            if now >= next_update_time:
                needs_full_update = True
                trigger_source = source_url
                break

        if needs_full_update:
            logging.info(
                f"Источник '{trigger_source}' инициировал полное обновление.")
            update_proxies(current_config)

            for source in current_config.get('sources', []):
                if source.get('enabled', False) and source.get('url'):
                    interval = parse_time_interval(source.get(
                        'update_interval_seconds'), default_interval)
                    source_schedules[source.get(
                        'url')] = time.time() + interval
            logging.debug("Расписание обновлено.")

        time.sleep(1)


class ProxyApiHandler(BaseHTTPRequestHandler):
    """
    Обработчик HTTP-запросов с тремя путями:
    1. /          - Публичная текстовая статусная страница
    2. /api/proxies - Защищенный JSON-эндпоинт для получения прокси
    3. *          - Ошибка 404
    """

    def do_GET(self):
        """Маршрутизирует запросы в зависимости от пути."""
        parsed_path = urlparse(self.path)

        if parsed_path.path == '/':
            self.send_status_page()
        elif parsed_path.path == '/api/proxies':
            self.handle_proxy_request(parsed_path)
        else:
            self.send_error_response(
                404, "Not Found", "Доступные эндпоинты: / и /api/proxies")

    def send_status_page(self):
        """Отправляет публичную страницу со статусом и документацией API в текстовом формате."""
        logging.debug(f"Запрос статусной страницы от {self.client_address[0]}")
        stats = {}
        with proxies_lock:
            total_proxies = len(PROXIES)
            for proxy in PROXIES:
                try:
                    proxy_type = proxy.split('://')[0]
                    stats[proxy_type] = stats.get(proxy_type, 0) + 1
                except IndexError:
                    continue

        with config_lock:
            auth_required = bool(CONFIG.get('api_keys'))

        # Формируем текстовый ответ
        response_lines = [
            "=========================================",
            "  Proxy-Fountain Status",
            "=========================================",
            f"Status: online",
            f"Total unique proxies: {total_proxies}\n",
            "Available by type:",
        ]
        if stats:
            for proxy_type, count in sorted(stats.items()):
                response_lines.append(f"  - {proxy_type.upper()}: {count}")
        else:
            response_lines.append("  (No proxies available yet)")

        response_lines.extend([
            "\n=========================================",
            "  API Documentation",
            "=========================================",
            "Endpoint: /api/proxies\n",
            "Parameters (pass in URL):",
            "  - type (optional): Filter by proxy type (e.g., 'socks5', 'http').",
        ])

        if auth_required:
            response_lines.insert(len(response_lines) - 1,
                                  "  - key (required): Your API access key.")
            response_lines.append("\nExample with key and filter:")
            response_lines.append(
                f"  /api/proxies?key=YOUR_API_KEY&type=socks5")
        else:
            response_lines.append("\nExample with filter:")
            response_lines.append(f"  /api/proxies?type=socks5")

        response_text = "\n".join(response_lines)

        self.send_response(200)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(response_text.encode('utf-8'))

    def handle_proxy_request(self, parsed_path):
        """Обрабатывает запросы на получение прокси с проверкой ключа."""
        with config_lock:
            current_config = CONFIG

        query_params = parse_qs(parsed_path.query)
        if current_config.get('api_keys'):
            client_key = query_params.get('key', [None])[0]
            if not client_key or client_key not in current_config.get('api_keys'):
                logging.warning(
                    f"Неудачная попытка доступа к API с IP {self.client_address[0]}")
                self.send_error_response(
                    403, "Access Denied", "Требуется валидный API ключ в параметре 'key'.")
                return

        with proxies_lock:
            proxies_to_send = list(PROXIES)

        proxy_type_filter = query_params.get('type', [None])[0]
        if proxy_type_filter:
            result_list = [p for p in proxies_to_send if p.startswith(
                f"{proxy_type_filter}://")]
        else:
            result_list = proxies_to_send

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(result_list, indent=2).encode('utf-8'))
        logging.debug(f"Успешный ответ API для {self.client_address[0]}")

    def send_error_response(self, code, title, message):
        self.send_response(code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(
            {"error": title, "message": message}).encode('utf-8'))

    def log_message(self, format, *args):
        # Подавляем стандартные логи веб-сервера, чтобы не дублировать информацию
        return


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


if __name__ == "__main__":
    if not load_and_update_config():
        print("[КРИТИЧЕСКАЯ ОШИБКА] Не удалось загрузить конфиг. Запуск отменен.")
        exit(1)

    with config_lock:
        setup_logging(CONFIG)

    logging.info("Инициализация сервиса Proxy-Fountain...")

    with config_lock:
        update_proxies(CONFIG)

    updater_thread = threading.Thread(
        target=background_updater_task, daemon=True)
    updater_thread.start()

    with config_lock:
        api_port = CONFIG.get('api_port', 8888)
        api_keys_enabled = bool(CONFIG.get('api_keys'))

    server_address = ('', api_port)
    httpd = ThreadingHTTPServer(server_address, ProxyApiHandler)

    logging.info(f"API-сервер запущен на http://localhost:{api_port}")
    if api_keys_enabled:
        logging.info("API требует ключ аутентификации.")
    else:
        logging.warning("API работает в открытом режиме без аутентификации.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Сервер остановлен.")
