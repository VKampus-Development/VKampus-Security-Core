/*
 * Copyright (C) 2026 pindeveloper
 * https://github.com/pindeveloper
 * 
 * ------------------------------------------------------------------
 * TRANSPARENCY AUDIT: TELEGRAM WEB APP DATA VALIDATION
 * ------------------------------------------------------------------
 * Этот код показывает наш механизм валидации Telegram WebAppData.
 * Он используется нашим сервером (VKampus API) для проверки того,
 * что запрос на вход действительно поступил из официального 
 * клиента Telegram, а не был подделан злоумышленником.
 * ------------------------------------------------------------------
 */
import crypto from "crypto"
export interface AuditedUser {
    telegram_id: number
    username?: string
    first_name: string
    last_name?: string
    photo_url?: string
    auth_date: number
}

/**
 * VALIDATION LOGIC
 * Проверка HMAC-SHA256 подписи данных, пришедших от клиента.
 * Использует стандартный алгоритм верификации, описанный в документации Telegram.
 * 
 * @param initData Строка window.Telegram.WebApp.initData
 * @param botToken Секретный токен бота (хранится только на сервере)
 */
export function audit_validateInitData(initData: string, botToken: string): boolean {
    try {
        const urlParams = new URLSearchParams(initData)
        const hash = urlParams.get("hash")
        urlParams.delete("hash")

        if (!hash) return false

        // Сортировка параметров по алфавиту
        const dataCheckString = Array.from(urlParams.entries())
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, value]) => `${key}=${value}`)
            .join("\n")

        // Создание секретного ключа
        const secretKey = crypto.createHmac("sha256", "WebAppData").update(botToken).digest()

        // Вычисление хеша
        const calculatedHash = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex")

        return calculatedHash === hash
    } catch (error) {
        return false // Если данные повреждены, аутентификация не проходит
    }
}

/**
 * EXTRACTION LOGIC
 * Извлечение СТРОГО минимально необходимых полей.
 * Мы прозрачно показываем, что даже если Telegram присылает больше 
 * данных о пользователе, ВКампус отсеивает всё лишнее прямо на входе.
 */
export function audit_extractUser(initData: string): AuditedUser | null {
    try {
        const urlParams = new URLSearchParams(initData)
        const userParam = urlParams.get("user")

        if (!userParam) return null

        const user = JSON.parse(userParam)

        // TRANSPARENCY CHECK:
        // Мы возвращаем и сохраняем только эти поля для работы профиля пользователя:
        return {
            telegram_id: user.id, // Уникальный идентификатор, необходимый для работы
            username: user.username, // Свободный никнейм
            first_name: user.first_name,
            last_name: user.last_name,
            photo_url: user.photo_url,
            auth_date: Number.parseInt(urlParams.get("auth_date") || "0"),
        }
    } catch (error) {
        return null
    }
}

/**
 * REPLAY ATTACK PROTECTION
 * Проверяем, не устарели ли данные авторизации (по умолчанию срок жизни 24 часа).
 * Если злоумышленник перехватит старый валидный initData, он не сможет по нему войти.
 */
export function isAuthDateValid(authDate: number, maxAgeSeconds = 86400): boolean {
    const now = Math.floor(Date.now() / 1000)
    const age = now - authDate

    if (age > maxAgeSeconds || age < 0) {
        return false
    }

    return true
}
