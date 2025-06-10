#!/bin/bash

# ==============================================================================
#   Универсальный скрипт для управления Docker-проектами
#   Версия 3.1: Улучшен интерфейс меню
# ==============================================================================

# --- Конфигурация ---
PROJECT_NAME=$(basename "$(pwd)")
HINT_COLUMN=30 

# --- Настройки и переменные ---
set -e 

# Цвета
C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_CYAN='\033[1;96m'
C_GRAY='\033[0;90m'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR" || exit

# --- Автоматическое определение команды docker-compose ---
DOCKER_COMPOSE_CMD=""
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
fi

# --- Проверки зависимостей ---
check_dependencies() {
    if ! command -v docker &> /dev/null; then
        echo -e "${C_RED}Ошибка: Docker не найден. Пожалуйста, установите Docker.${C_RESET}"
        exit 1
    fi

    if [ -z "$DOCKER_COMPOSE_CMD" ]; then
        echo -e "${C_RED}Ошибка: Не найдена ни команда 'docker-compose', ни 'docker compose'.${C_RESET}"
        echo -e "${C_YELLOW}Пожалуйста, установите плагин Docker Compose (рекомендуется).${C_RESET}"
        echo -e "${C_CYAN}Пример для Ubuntu/Debian (после настройки репозитория Docker):${C_RESET}"
        echo -e "${C_GRAY}sudo apt-get update && sudo apt-get install docker-compose-plugin${C_RESET}"
        exit 1
    fi
    
    if [ ! -f "docker-compose.yml" ] && [ ! -f "docker-compose.yaml" ]; then
        echo -e "${C_RED}Ошибка: Файл docker-compose.yml или docker-compose.yaml не найден в текущей директории.${C_RESET}"
        exit 1
    fi
}

# --- Функции управления ---

start_project() {
    echo -e "${C_GREEN}✅ Запуск проекта '${PROJECT_NAME}'...${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD up -d
    echo -e "${C_GREEN}Проект успешно запущен.${C_RESET}"
}

stop_project() {
    echo -e "${C_YELLOW}🛑 Остановка проекта '${PROJECT_NAME}'...${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD down
    echo -e "${C_YELLOW}Проект успешно остановлен.${C_RESET}"
}

restart_project() {
    echo -e "${C_CYAN}🔄 Перезапуск проекта '${PROJECT_NAME}'...${C_RESET}"
    stop_project
    start_project
}

update_project() {
    echo -e "${C_CYAN}🚀 Обновление проекта '${PROJECT_NAME}'...${C_RESET}"
    echo -e "${C_GRAY}1/3: Скачивание новых образов...${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD pull
    echo -e "${C_GRAY}2/3: Перезапуск контейнеров с новыми образами...${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD up -d --remove-orphans
    echo -e "${C_GREEN}🎉 Проект успешно обновлен и запущен!${C_RESET}"
}

rebuild_project() {
    echo -e "${C_CYAN}🛠️ Принудительное пересоздание контейнеров...${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD up -d --force-recreate
    echo -e "${C_GREEN}Контейнеры успешно пересозданы.${C_RESET}"
}

show_status() {
    echo -e "${C_CYAN}📊 Статус контейнеров для '${PROJECT_NAME}':${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD ps
}

show_logs() {
    echo -e "${C_GRAY}📜 Логи проекта '${PROJECT_NAME}' (нажмите Ctrl+C для выхода)...${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD logs -f --tail="100"
}

open_shell() {
    local service
    service=$1
    if [ -z "$service" ]; then
        echo -e "${C_YELLOW}Доступные сервисы для подключения:${C_RESET}"
        sudo $DOCKER_COMPOSE_CMD ps --services
        read -p "Введите имя сервиса, к которому хотите подключиться: " service
        if [ -z "$service" ]; then echo -e "${C_RED}Отменено.${C_RESET}"; exit 1; fi
    fi
    echo -e "${C_GREEN}Подключение к '$service'...${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD exec "$service" /bin/bash || sudo $DOCKER_COMPOSE_CMD exec "$service" /bin/sh
}

prune_system() {
    echo -e "${C_RED}ВНИМАНИЕ: Это действие удалит все неиспользуемые Docker-объекты В СИСТЕМЕ.${C_RESET}"
    read -p "Вы уверены, что хотите продолжить? [y/N]: " confirmation
    if [[ "$confirmation" != "y" && "$confirmation" != "Y" ]]; then echo "Отменено."; exit 0; fi
    echo -e "${C_YELLOW}Очистка системы Docker...${C_RESET}"
    sudo docker system prune -af
}

destroy_project() {
    echo -e "${C_RED}!!! ВНИМАНИЕ: НЕОБРАТИМОЕ ДЕЙСТВИЕ !!!${C_RESET}"
    echo -e "${C_YELLOW}Эта команда полностью удалит все контейнеры, сети, ТОМА (ДАННЫЕ) и образы, связанные с проектом '${PROJECT_NAME}'.${C_RESET}"
    echo -e "${C_RED}Все данные, хранящиеся в томах Docker, будут ПОТЕРЯНЫ НАВСЕГДА.${C_RESET}"
    read -p "Для подтверждения введите 'yes': " confirmation

    if [[ "$confirmation" != "yes" ]]; then
        echo "Отменено."
        exit 0
    fi

    echo -e "${C_YELLOW}Начинаю полное удаление проекта...${C_RESET}"
    sudo $DOCKER_COMPOSE_CMD down -v --rmi all
    echo -e "${C_GREEN}✅ Проект '${PROJECT_NAME}' полностью удален.${C_RESET}"
}


# --- Интерактивное меню ---

show_interactive_menu() {
    local format_default=" [${C_YELLOW}%s${C_RESET}] %s\033[${HINT_COLUMN}G${C_GRAY}%s${C_RESET}\n"
    local format_danger=" [${C_YELLOW}%s${C_RESET}] %s\033[${HINT_COLUMN}G${C_RED}%s${C_RESET}\n"
    
    clear
    echo -e "${C_CYAN}======================================================================${C_RESET}"
    echo -e "   Меню управления для: ${C_GREEN}${PROJECT_NAME}${C_RESET} ${C_GRAY}(исп. $DOCKER_COMPOSE_CMD)${C_RESET}"
    echo -e "${C_CYAN}======================================================================${C_RESET}"
    printf "$format_default" "1" "Запустить проект" "Запускает контейнеры (up -d)"
    printf "$format_default" "2" "Остановить проект" "Останавливает контейнеры (down)"
    printf "$format_default" "3" "Перезапустить проект" "Полностью перезапускает (down & up)"
    printf "$format_default" "4" "Обновить" "Скачивает новые образы (pull & up)"
    printf "$format_default" "5" "Показать статус" "Показывает статус контейнеров (ps)"
    printf "$format_default" "6" "Показать логи" "Выводит логи в реальном времени"
    echo ""
    echo -e "${C_GRAY}--- Обслуживание и удаление ---${C_RESET}"
    printf "$format_default" "7" "Войти в контейнер" "Подключается к shell сервиса"
    printf "$format_default" "8" "Пересоздать" "Принудительно пересоздает контейнеры"
    printf "$format_danger"  "9" "Очистить систему" "Удаляет неисп. объекты Docker"
    printf "$format_danger"  "10" "УДАЛИТЬ ПРОЕКТ" "Удаляет контейнеры, тома и образы"
    echo ""
    printf "$format_default" "0" "Выход" "Завершает работу скрипта"
    echo -e "${C_CYAN}======================================================================${C_RESET}"

    read -p "Выберите действие [0-10]: " choice

    case "$choice" in
        1) start_project ;; 2) stop_project ;; 3) restart_project ;;
        4) update_project ;; 5) show_status ;; 6) show_logs ;;
        7) open_shell ;; 8) rebuild_project ;; 9) prune_system ;;
        10) destroy_project ;;
        0) echo "Выход."; exit 0 ;;
        *) echo -e "${C_RED}Неверный выбор.${C_RESET}"; sleep 1; show_interactive_menu ;;
    esac
}

# --- Основная логика ---
check_dependencies

if [ -z "$1" ]; then
    show_interactive_menu
else
    case "$1" in
        start|stop|restart|update|rebuild|status|logs|prune|destroy)
            "${1}_project"
            ;;
        shell) open_shell "$2" ;;
        *)
            echo -e "${C_RED}Неизвестная команда: $1${C_RESET}"
            exit 1
            ;;
    esac
fi

exit 0