/**
 *  Copyright (C) 2026 pindeveloper
 * https://github.com/pindeveloper
 * ------------------------------------------------------------------
 * TRANSPARENCY AUDIT: TELEGRAM ID ANONYMIZATION
 * ------------------------------------------------------------------
 * ВКампус — это полностью анонимная платформа.
 * Чтобы защитить личность наших студентов, мы не сохраняем в базу данных
 * (открытым текстом) ваш реальный telegram_id в таблицу постов и комментариев.
 * 
 * Мы используем HMAC-SHA256 хеширование с секретной "солью", хранящейся 
 * только в переменных окружения (environment variables) нашего сервера.
 * ------------------------------------------------------------------
 */
import { createHmac } from "crypto"
/**
 * Хеширует Telegram ID пользователя перед записью в публичные/связанные таблицы БД.
 * 
 * @param telegramId Оригинальный числовой ID от Telegram
 * @returns 64-символьная шестнадцатеричная строка (HMAC-SHA256 hash)
 */
export function hashTelegramId(telegramId: number | string): string {
    const secret = process.env.TELEGRAM_ID_SECRET

    if (!secret) {
        throw new Error("Critical Security Error: TELEGRAM_ID_SECRET is not set")
    }

    // Алгоритм необратимо хеширует ID.
    // Если "secret" не скомпрометирован, из полученного хеша невозможно
    // восстановить исходный telegramId, даже если база данных утечет.
    return createHmac("sha256", secret)
        .update(String(telegramId))
        .digest("hex")
}
