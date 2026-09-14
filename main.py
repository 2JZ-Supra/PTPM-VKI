import os
import sys
import re
import logging
import hashlib

def setup_logging():
    if not os.path.exists('logs'):
        os.makedirs('logs')

    log_format = "%(asctime)s | [%(levelname)-7s] | %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    logging.basicConfig(
        level=logging.DEBUG,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("logs/file_text.log", encoding="utf-8")
        ]
    )

    logging.info("Логгер успешно сконфигурирован")
    logging.info("Приложение запущено")

def mask_password(password: str) -> str:
    if not password:
        return "empty"
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def validate_registration(login: str, password: str, confirm_password: str) -> tuple[bool, str]:
    if not login:
        return False, "Логин не может быть пустым."

    blacklist = {"admin", "root", "user", "test", "guest", "qwerty", "123456"}
    if login.lower() in blacklist:
        return False, "Логин находится в черном списке запрещенных."

    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    phone_regex = r"^\+\d{1,3}-\d{3}-\d{3}-\d{4}$"
    string_regex = r"^[a-zA-Z0-9_]{5,}$"

    is_email = re.match(email_regex, login)
    is_phone = re.match(phone_regex, login)

    if not (is_email or is_phone):
        if len(login) < 5:
            return False, "Логин (строка) должен содержать минимум 5 символов."
        if not re.match(r"^[a-zA-Z0-9_]+$", login):
            return False, "Логин (строка) может содержать только латиницу, цифры и знак подчеркивания."
        if not re.match(string_regex, login):
            return False, "Логин не соответствует формату телефона, email или обычной строки."

    if not password:
        return False, "Пароль не может быть пустым."

    if len(password) < 7:
        return False, "Пароль должен содержать минимум 7 символов."

    if re.search(r"[a-zA-Z]", password):
        return False, "Пароль может содержать только кириллицу, цифры и спецсимволы (латиница запрещена)."

    allowed_chars_regex = r"^[А-Яа-я0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+$"
    if not re.match(allowed_chars_regex, password):
        return False, "Пароль содержит недопустимые символы."

    if not re.search(r"[А-Я]", password):
        return False, "Пароль должен содержать минимум одну заглавную букву кириллицы."

    if not re.search(r"[а-я]", password):
        return False, "Пароль должен содержать минимум одну строчную букву кириллицы."

    if not re.search(r"\d", password):
        return False, "Пароль должен содержать минимум одну цифру."

    special_chars_regex = r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]"
    if not re.search(special_chars_regex, password):
        return False, "Пароль должен содержать минимум один спецсимвол."

    if password != confirm_password:
        return False, "Пароль и подтверждение пароля не совпадают."

    return True, ""

def process_registration(login, password, confirm_password):
    masked_pass = mask_password(password)
    masked_confirm = mask_password(confirm_password)

    try:
        logging.debug(
            f"Попытка регистрации. Входные данные: login='{login}', pass='{masked_pass}', confirm='{masked_confirm}'")

        is_valid, message = validate_registration(login, password, confirm_password)

        if is_valid:
            logging.info(
                f"Успешный запрос. Параметры: login='{login}', pass='{masked_pass}'. Результат: True. Сообщение: ''")
            return True, ""
        else:
            logging.warning(
                f"Неуспешный запрос. Параметры: login='{login}', pass='{masked_pass}'. Результат: False. Причина: {message}")
            return False, message

    except Exception as e:
        logging.error("Что-то пошло не так...")
        logging.exception("Заход в блок обработки исключения:")
        return False, f"Внутренняя ошибка сервера: {str(e)}"

def main():
    setup_logging()

    print("\n--- Тестирование валидации (Вариант 2) ---\n")

    test_cases = [
        ("+7-999-123-4567", "Пароль1!", "Пароль1!"),
        ("user_mail@example.com", "Кириллица1@", "Кириллица1@"),
        ("valid_user", "СложныйПароль#1", "СложныйПароль#1"),

        ("", "Пароль1!", "Пароль1!"),
        ("admin", "Пароль1!", "Пароль1!"),
        ("usr", "Пароль1!", "Пароль1!"),
        ("user name", "Пароль1!", "Пароль1!"),

        ("valid_user", "", ""),
        ("valid_user", "Short1!", "Short1!"),
        ("valid_user", "ПарольPassword1!", "ПарольPassword1!"),
        ("valid_user", "пароль1!", "пароль1!"),
        ("valid_user", "ПАРОЛЬ1!", "ПАРОЛЬ1!"),
        ("valid_user", "Пароль!", "Пароль!"),
        ("valid_user", "Пароль1", "Пароль1"),
        ("valid_user", "Пароль1!", "Пароль2!")
    ]

    for login, pwd, confirm in test_cases:
        result, msg = process_registration(login, pwd, confirm)
        status = "OK" if result else "FAIL"
        print(f"[{status}] Login: '{login}' | Pass: '{pwd}' | Confirm: '{confirm}'")
        if not result:
            print(f"       -> Причина: {msg}")
        print("-" * 50)


if __name__ == "__main__":
    main()