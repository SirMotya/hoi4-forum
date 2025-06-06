# Forum on Go | Форум на Go

[English](#english) | [Русский](#russian)

# English

A web forum application developed in Go. The project is a fully functional forum with registration system, authorization, topic creation, comments, and rating system.

## Main Features

- 👤 User registration and authorization
- 📝 Create and view topics
- 💬 Comment on topics
- 👍 Like/Dislike system
- 🏆 User reputation system
- 👨‍💼 User profiles
- 📊 Activity statistics

## Technologies

- Go 1.23
- SQLite3
- Gorilla Sessions
- bcrypt for password hashing
- HTML Templates

## Installation and Launch

1. Clone the repository:
```bash
git clone https://github.com/your-username/forum-go
cd forum-go
```

2. Install dependencies:
```bash
go mod tidy
```

3. Run the application:
```bash
go run main.go
```

The application will be available at: http://localhost:8082

## Project Structure

```
.
├── main.go          # Main application file
├── create_db.go     # Database initialization
├── static/          # Static files (CSS, JS)
│   └── css/
│       └── style.css
└── templates/       # HTML templates
```

## Database

The project uses SQLite3 for data storage. The database is created automatically on first launch.

## Security

- Passwords are hashed using bcrypt
- XSS attack protection
- Secure user sessions

---

# Russian

Веб-приложение форума, разработанное на языке Go. Проект представляет собой полнофункциональный форум с системой регистрации, авторизации, созданием тем, комментариями и системой рейтинга.

## Основные функции

- 👤 Регистрация и авторизация пользователей
- 📝 Создание и просмотр тем
- 💬 Комментирование тем
- 👍 Система лайков и дизлайков
- 🏆 Система репутации пользователей
- 👨‍💼 Профили пользователей
- 📊 Статистика активности

## Технологии

- Go 1.23
- SQLite3
- Gorilla Sessions
- bcrypt для хеширования паролей
- HTML Templates

## Установка и запуск

1. Клонируйте репозиторий:
```bash
git clone https://github.com/ваш-username/forum-go
cd forum-go
```

2. Установите зависимости:
```bash
go mod tidy
```

3. Запустите приложение:
```bash
go run main.go
```

Приложение будет доступно по адресу: http://localhost:8082

## Структура проекта

```
.
├── main.go          # Основной файл приложения
├── create_db.go     # Инициализация базы данных
├── static/          # Статические файлы (CSS, JS)
│   └── css/
│       └── style.css
└── templates/       # HTML шаблоны
```

## База данных

Проект использует SQLite3 для хранения данных. База данных создается автоматически при первом запуске приложения.

## Безопасность

- Пароли хешируются с использованием bcrypt
- Защита от XSS-атак
- Безопасные сессии пользователей
