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
from collections import defaultdict
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
CONFIG = {}
config_lock = threading.Lock()
PROXY_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})")


def parse_time_interval(value, default):
    """Безопасно вычисляет временной интервал из строки или числа."""
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            # Используем eval в безопасном режиме для выполнения только простых математических операций.
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

    # Обработчик для записи в файл с ротацией по времени
    fh = logging.handlers.TimedRotatingFileHandler(
        log_file, when='D', interval=1, backupCount=7, encoding='utf-8')
    fh.setLevel(file_level)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Обработчик для вывода в консоль
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


# =============================================================================
#   КЛАСС-МЕНЕДЖЕР ПРОКСИ
# =============================================================================
class ProxyManager:
    """Инкапсулирует всю логику хранения, обновления и предоставления прокси."""

    def __init__(self):
        self._proxies_by_source = {}  # {'url': {'proxy1', ...}}
        self._all_proxies = set()
        self._lock = threading.Lock()

    def _rebuild_all_proxies(self):
        """Приватный метод для пересборки общего списка. Должен вызываться под замком."""
        self._all_proxies = set().union(*self._proxies_by_source.values())
        logging.info(
            f"Общий список пересобран. Актуальных прокси: {len(self._all_proxies)}")

    def update_source(self, source_config):
        """Атомарно обновляет один источник и пересобирает общий список."""
        url = source_config.get('url')
        proxy_type = source_config.get('type', 'http')
        logging.info(f"Начало обновления источника: {url}")

        source_proxies = set()
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            lines = response.text.splitlines()
            found_count = 0
            for line in lines:
                match = PROXY_PATTERN.search(line)
                if match:
                    source_proxies.add(f"{proxy_type}://{match.group(1)}")
                    found_count += 1
            logging.info(
                f"  - ({proxy_type.upper()}) Найдено: {found_count} из {url}")

            # Атомарное обновление под единым замком
            with self._lock:
                self._proxies_by_source[url] = source_proxies
                self._rebuild_all_proxies()

        except requests.RequestException as e:
            logging.error(f"  - Не удалось получить данные с {url}: {e}")
            # В случае ошибки не меняем буфер, чтобы не потерять старые, возможно рабочие, прокси

    def purge_inactive_sources(self, active_urls):
        """Удаляет "зомби-данные" от источников, которых больше нет в конфиге."""
        with self._lock:
            # Находим URLы, которые есть в нашем буфере, но отсутствуют в активных источниках конфига
            inactive_urls = set(
                self._proxies_by_source.keys()) - set(active_urls)
            if not inactive_urls:
                return

            logging.info(
                f"Очистка неактивных источников: {', '.join(inactive_urls)}")
            for url in inactive_urls:
                del self._proxies_by_source[url]

            self._rebuild_all_proxies()

    def get_snapshot(self):
        """Возвращает потокобезопасную копию (снимок) текущего списка всех прокси."""
        with self._lock:
            return self._all_proxies.copy()


# =============================================================================
#   ФОНОВЫЕ ПРОЦЕССЫ
# =============================================================================
def background_updater_task(proxy_manager):
    """Планировщик, который управляет вызовами ProxyManager."""
    threading.current_thread().name = "Updater"
    source_schedules = {}
    config_reload_timer = time.time() + 60

    # Первоначальное полное обновление всех источников
    logging.info("Первоначальное полное заполнение всех прокси-буферов...")
    with config_lock:
        current_config = CONFIG.copy()
    for source in current_config.get('sources', []):
        if source.get('enabled', False):
            proxy_manager.update_source(source)

    # Установка первоначального расписания
    default_interval = parse_time_interval(
        current_config.get('default_update_interval_seconds'), 3600)
    for source in current_config.get('sources', []):
        if source.get('enabled', False) and source.get('url'):
            interval = parse_time_interval(source.get(
                'update_interval_seconds'), default_interval)
            source_schedules[source.get('url')] = time.time() + interval
    logging.debug("Планировщик инициализирован.")

    while True:
        now = time.time()

        # Периодическая проверка и перезагрузка конфига
        if now >= config_reload_timer:
            if load_and_update_config():
                logging.debug("Файл конфигурации успешно перезагружен.")
                with config_lock:
                    active_urls = [s['url'] for s in CONFIG.get(
                        'sources', []) if s.get('enabled')]
                proxy_manager.purge_inactive_sources(active_urls)
            config_reload_timer = now + 60

        with config_lock:
            current_config = CONFIG.copy()
        default_interval = parse_time_interval(
            current_config.get('default_update_interval_seconds'), 3600)

        # Обновляем все "просроченные" источники
        for source in current_config.get('sources', []):
            if source.get('enabled', False) and source.get('url'):
                # Используем .get с 0, чтобы новые источники сразу обновлялись
                if now >= source_schedules.get(source.get('url'), 0):
                    proxy_manager.update_source(source)
                    # Обновляем расписание только для этого источника
                    interval = parse_time_interval(source.get(
                        'update_interval_seconds'), default_interval)
                    source_schedules[source.get(
                        'url')] = time.time() + interval

        time.sleep(1)


# =============================================================================
#   API-СЕРВЕР
# =============================================================================
class ProxyApiHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP-запросов, который работает с ProxyManager."""

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
        all_proxies = self.server.proxy_manager.get_snapshot()
        stats = defaultdict(int)
        for proxy in all_proxies:
            stats[proxy.split('://')[0]] += 1

        with config_lock:
            auth_required = bool(CONFIG.get('api_keys'))

        response_lines = [
            "=========================================",
            "  Proxy-Fountain Status",
            "=========================================",
            f"Status: online",
            f"Total unique proxies: {len(all_proxies)}\n",
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
            "  - format (optional): Output format. 'json' (default) or 'text'.",
        ])

        if auth_required:
            response_lines.insert(len(response_lines) - 2,
                                  "  - key (required): Your API access key.")
            response_lines.append("\nExample with all options:")
            response_lines.append(
                f"  /api/proxies?key=YOUR_API_KEY&type=socks5&format=text")
        else:
            response_lines.append("\nExample with all options:")
            response_lines.append(f"  /api/proxies?type=socks5&format=text")

        response_text = "\n".join(response_lines)

        self.send_response(200)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(response_text.encode('utf-8'))

    def handle_proxy_request(self, parsed_path):
        """Обрабатывает запросы на получение прокси с проверкой ключа и формата."""
        with config_lock:
            current_config = CONFIG

        query_params = parse_qs(parsed_path.query)
        # Проверка аутентификации
        if current_config.get('api_keys'):
            client_key = query_params.get('key', [None])[0]
            if not client_key or client_key not in current_config.get('api_keys'):
                logging.warning(
                    f"Неудачная попытка доступа к API с IP {self.client_address[0]}")
                self.send_error_response(
                    403, "Access Denied", "Требуется валидный API ключ в параметре 'key'.")
                return

        # Получаем "снимок" актуальных прокси от менеджера
        proxies_to_send = self.server.proxy_manager.get_snapshot()

        # Фильтруем по типу
        proxy_type_filter = query_params.get('type', [None])[0]
        # Сортируем для консистентного вывода
        result_list = sorted(list(proxies_to_send))
        if proxy_type_filter:
            result_list = [p for p in result_list if p.startswith(
                f"{proxy_type_filter}://")]

        # Определяем формат вывода
        output_format = query_params.get('format', ['json'])[0].lower()

        if output_format == 'json':
            self.send_response(200)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(result_list, indent=2).encode('utf-8'))
        elif output_format == 'text':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            text_response = "\n".join(result_list)
            self.wfile.write(text_response.encode('utf-8'))
        else:
            self.send_error_response(
                400, "Bad Request", "Неверный формат. Доступные форматы: 'json', 'text'.")

        logging.debug(
            f"Успешный ответ API для {self.client_address[0]} в формате {output_format.upper()}")

    def send_error_response(self, code, title, message):
        self.send_response(code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(
            {"error": title, "message": message}).encode('utf-8'))

    def log_message(self, format, *args):
        # Подавляем стандартные логи веб-сервера, чтобы они не дублировали наши
        return


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Расширенный сервер, который содержит ссылку на наш proxy_manager."""

    def __init__(self, server_address, RequestHandlerClass, proxy_manager):
        super().__init__(server_address, RequestHandlerClass)
        self.proxy_manager = proxy_manager


# =============================================================================
#   ТОЧКА ВХОДА
# =============================================================================
if __name__ == "__main__":
    if not load_and_update_config():
        print("[КРИТИЧЕСКАЯ ОШИБКА] Не удалось загрузить конфиг. Запуск отменен.")
        exit(1)

    with config_lock:
        setup_logging(CONFIG)

    logging.info("Инициализация сервиса Proxy-Fountain...")

    # Создаем единый экземпляр менеджера
    proxy_manager_instance = ProxyManager()

    # Запускаем фоновый поток, передав ему ссылку на менеджер
    updater_thread = threading.Thread(
        target=background_updater_task,
        args=(proxy_manager_instance,),
        daemon=True
    )
    updater_thread.start()

    with config_lock:
        api_port = CONFIG.get('api_port', 8888)
        api_keys_enabled = bool(CONFIG.get('api_keys'))

    server_address = ('', api_port)
    # Передаем ссылку на менеджер в наш сервер, чтобы обработчики могли его использовать
    httpd = ThreadingHTTPServer(
        server_address, ProxyApiHandler, proxy_manager_instance)

    logging.info(f"API-сервер запущен на http://localhost:{api_port}")
    logging.info(
        f"Статус сервиса доступен по адресу http://localhost:{api_port}/")
    if api_keys_enabled:
        logging.info("API требует ключ аутентификации.")
    else:
        logging.warning("API работает в открытом режиме без аутентификации.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Сервер остановлен.")
