# Proxy-Fountain

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg?logo=docker)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Proxy-Fountain** — это простой, легковесный и умный прокси-провайдер на Python, упакованный в Docker-контейнер для максимальной простоты развертывания и управления. Он автоматически скачивает, парсит и поставляет списки прокси через простое и защищенное API. Идеально подходит для скрапинга, автоматизации и других задач, требующих постоянного потока свежих прокси.

## 🚀 Основные возможности

-   **Простое развертывание:** Запуск одной командой благодаря Docker и Docker Compose.
-   **Простая конфигурация:** Все настройки в одном читаемом `config.yaml` файле.
-   **Умный парсер:** Автоматически находит прокси в формате `IP:PORT` из любых источников, не требуя сложных правил.
-   **Индивидуальные таймеры:** Задавайте разную частоту обновления для каждого списка прокси.
-   **Гибкое время:** Указывайте интервалы в секундах или в виде простых математических выражений (`60 * 5` для 5 минут).
-   **Защищенное API:** Ограничьте доступ к вашим прокси с помощью API-ключей.
-   **Надежное логирование:** Ведение логов в файл с автоматической ротацией (каждый день) и очисткой (хранятся 7 дней).
-   **Статусная страница:** Дружелюбная "витрина" сервиса с краткой статистикой и документацией API.
-   **Автозапуск:** Контейнер автоматически перезапускается при сбоях и после перезагрузки хост-машины.

## ⚙️ Установка и настройка

### Предварительные требования

-   [Docker](https://docs.docker.com/get-docker/)
-   [Docker Compose](https://docs.docker.com/compose/install/)

### Шаги установки

1.  **Клонируйте репозиторий:**
    ```sh
    git clone https://github.com/your-username/proxy-fountain.git
    cd proxy-fountain
    ```

2.  **Настройте `config.yaml`:**
    Создайте файл `config.yaml` из примера ниже или отредактируйте существующий. Это единственный файл, который вам нужно настроить.

    #### Пример `config.yaml`:
    ```yaml
    # Порт, на котором будет работать API. Убедитесь, что он совпадает с портом в docker-compose.yml
    api_port: 8888

    # Настройки логирования. Путь указан относительно рабочей директории в контейнере.
    logging:
      log_file: "logs/proxy_fountain.log"
      log_level_console: "INFO"
      log_level_file: "DEBUG"

    # Интервал обновления по умолчанию (можно использовать математику)
    default_update_interval_seconds: 60 * 60 # 1 час

    # Ключи доступа к API (если список пуст, API будет открытым)
    api_keys:
      - "super-secret-key-for-app1"

    # Список источников прокси
    sources:
      - url: https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt
        type: socks5
        enabled: true
        update_interval_seconds: 60 * 5 # 5 минут

      - url: https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt
        type: http
        enabled: true
        # Использует интервал по умолчанию
    ```

## ▶️ Запуск и управление

Управление сервисом осуществляется с помощью Docker Compose из корневой папки проекта.

-   **Первый запуск (сборка образа и старт в фоне):**
    ```sh
    docker compose up --build -d
    ```

-   **Просмотр логов в реальном времени:**
    ```sh
    docker compose logs -f
    ```
    (Нажмите `Ctrl+C` для выхода)

-   **Остановка сервиса:**
    ```sh
    docker compose down
    ```

-   **Перезапуск сервиса (например, после изменения `config.yaml`):**
    ```sh
    docker compose restart
    ```

-   **Последующие запуски (без пересборки образа):**
    ```sh
    docker compose up -d
    ```

## 📡 Использование API

### 1. Статусная страница (без ключа)

Откройте в браузере `http://localhost:8888/` (замените порт, если меняли). Вы увидите простую текстовую страницу с информацией о состоянии сервиса, количестве доступных прокси и документацией API.

**Пример ответа:**
```
=========================================
  Proxy-Fountain Status
=========================================
Status: online
Total unique proxies: 2345

Available by type:
  - HTTP: 890
  - SOCKS5: 1455

=========================================
  API Documentation
=========================================
Endpoint: /api/proxies

Parameters (pass in URL):
  - key (required): Your API access key.
  - type (optional): Filter by proxy type (e.g., 'socks5', 'http').

Example with key and filter:
  /api/proxies?key=YOUR_API_KEY&type=socks5
```

### 2. Получение прокси (требует ключ)

Эндпоинт: `/api/proxies`

Параметры передаются через URL:
-   `key` (обязательный, если `api_keys` в конфиге не пуст): Ваш ключ доступа.
-   `type` (опциональный): Тип прокси для фильтрации (`socks5`, `http`, `socks4` и т.д.).

#### Примеры запросов:

-   **Получить все SOCKS5 прокси:**
    ```sh
    curl "http://localhost:8888/api/proxies?key=super-secret-key-for-app1&type=socks5"
    ```

-   **Получить все доступные прокси (без фильтрации):**
    ```sh
    curl "http://localhost:8888/api/proxies?key=super-secret-key-for-app1"
    ```

-   **Пример неудачного запроса (неверный ключ):**
    ```sh
    curl "http://localhost:8888/api/proxies?key=wrong-key"
    ```
    Ответ:
    ```json
    {
      "error": "Access Denied",
      "message": "Требуется валидный API ключ в параметре 'key'."
    }
    ```

## 📂 Структура проекта

```
/proxy-fountain/
|
├── 📂 logs/               # Папка для лог-файлов (создается автоматически).
|
├── 📄 .gitignore           # Исключения для Git.
├── 📄 config.yaml          # Ваш главный файл конфигурации.
├── 🐳 Dockerfile           # Инструкция по сборке Docker-образа.
├── 🐳 docker-compose.yml    # Файл для управления контейнером.
├── 🐍 proxy_fountain.py     # Основной код приложения.
└── 📋 requirements.txt     # Список Python-зависимостей.
```

## 📜 Лицензия

Этот проект распространяется под лицензией MIT. Подробности смотрите в файле `LICENSE`.