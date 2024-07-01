# 🔒 FastAPI JWT Authentication

**FastAPI JWT Authentication** — это демонстрационное приложение, показывающее, как можно реализовать аутентификацию и авторизацию с использованием JWT (JSON Web Tokens) на базе [FastAPI](https://fastapi.tiangolo.com/).

## 🛠️ Возможности

- **Аутентификация через JWT:** Пользователь получает JWT токен после успешного логина.
- **Авторизация:** Разделение доступа для пользователей с разными ролями (`admin` и `user`).
- **Защищенные эндпоинты:** Доступ к эндпоинтам разрешен только при наличии валидного JWT токена.
- **Использование стандартов:** Реализована аутентификация через [OAuth2](https://oauth.net/2/) и [JWT](https://jwt.io/).

## 📋 Требования

- **Python 3.9+**
- **FastAPI**
- **PyJWT**
- **python-multipart** (для работы с реквест-формой OAuth2)

## 🚀 Установка и Запуск

### Локально

1. **Клонируйте репозиторий:**

    ```bash
    git clone https://github.com/artyoma2000/fastapi-jwt-auth.git
    cd fastapi-jwt-auth
    ```

2. **Создайте виртуальное окружение и активируйте его:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # Для Windows: venv\Scripts\activate
    ```

3. **Установите зависимости:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Запустите приложение:**

    ```bash
    uvicorn main:app --reload
    ```

### Через Docker

1. **Клонируйте репозиторий:**

    ```bash
    git clone https://github.com/artyoma2000/fastapi-jwt-auth.git
    cd fastapi-jwt-auth
    ```

2. **Постройте и запустите Docker-контейнер:**

    ```bash
    docker build -t fastapi-jwt-auth .
    docker run -d -p 8000:8000 fastapi-jwt-auth
    ```

3. **Приложение будет доступно по адресу:**

    ```
    http://localhost:8000
    ```

## 📖 Примеры использования

### Получение JWT токена

Отправьте POST запрос на `/token/` с данными пользователя:

```bash
curl -X POST "http://localhost:8000/token/" -d "username=user&password=userpass"
```

### Доступ к защищенным эндпоинтам

Используйте полученный JWT токен для доступа к защищенным эндпоинтам. Пример для доступа к эндпоинту `/user/`:

```bash
curl -H "Authorization: Bearer <your-token>" "http://localhost:8000/user/"
```

## 📂 Структура проекта

```plaintext
.
├── main.py            # Основной файл приложения
├── requirements.txt   # Зависимости проекта
└── README.md          # Описание проекта
```

## 🔒 Безопасность

- **Секретный ключ:** В продакшене используйте надежно сгенерированный секретный ключ. Никогда не храните его в открытом виде в коде.
- **Хранение паролей:** Никогда не храните пароли в открытом виде. Используйте безопасные методы хэширования с солью.
- **Срок жизни токенов:** Рекомендуется устанавливать срок жизни токенов и обновлять их по мере необходимости.

## 🧑‍💻 Контрибуция

Мы приветствуем любые вклады! Пожалуйста, создайте [issue](https://github.com/artyoma2000/fastapi-jwt-auth/issues) или отправьте [pull request](https://github.com/artyoma2000/fastapi-jwt-auth/pulls).

