"""
JWT-аутентификация (self-issued HMAC-SHA256).

Модуль реализует выпуск и валидацию JWT-токенов без внешнего IdP.
Ключ подписи берётся из переменной окружения PHANTOM_JWT_SECRET.
"""

from __future__ import annotations

import json
import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import jwt  # PyJWT

logger = logging.getLogger("phantom.api.auth")

# Минимальная длина секрета (256 бит = 32 байта)
_MIN_SECRET_LENGTH = 32
# Время жизни access-токена (30 минут)
_ACCESS_TTL_SECONDS = 30 * 60
# Время жизни refresh-токена (7 дней)
_REFRESH_TTL_SECONDS = 7 * 24 * 3600
# Алгоритм подписи
_ALGORITHM = "HS256"
# Издатель токена
_ISSUER = "phantom-daemon"


@dataclass(frozen=True)
class TokenClaims:
    """Распарсенные данные из JWT-токена."""

    sub: str
    role: str
    token_type: str  # "access" | "refresh"
    exp: int
    iat: int
    jti: str


class JWTProvider:
    """
    Провайдер JWT-токенов с HMAC-SHA256.

    Безопасность:
    - Секрет >= 32 байт (256 бит)
    - Constant-time верификация подписи (PyJWT использует hmac.compare_digest)
    - jti для предотвращения replay-атак
    - Раздельные access/refresh токены
    """

    def __init__(
        self,
        secret: str | None = None,
        access_ttl: int = _ACCESS_TTL_SECONDS,
        refresh_ttl: int = _REFRESH_TTL_SECONDS,
        revoked_store_path: str | None = None,
    ) -> None:
        self._secret = secret or os.getenv("PHANTOM_JWT_SECRET", "").strip()
        if not self._secret:
            raise ValueError(
                "JWT secret не задан. Установите переменную окружения "
                "PHANTOM_JWT_SECRET (минимум 32 символа)"
            )
        if len(self._secret) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"JWT secret слишком короткий: {len(self._secret)} < {_MIN_SECRET_LENGTH} символов"
            )
        self._access_ttl = max(60, access_ttl)
        self._refresh_ttl = max(300, refresh_ttl)
        # Отозванные jti с временем отзыва (пишутся на диск при доступности store).
        self._revoked_jti: dict[str, float] = {}
        self._max_revoked = 10000
        self._revoked_lock = threading.Lock()
        store_raw = revoked_store_path or os.getenv(
            "PHANTOM_JWT_REVOKED_STORE", "/var/lib/phantom/jwt_revoked.json"
        )
        self._revoked_store_path = Path(str(store_raw)).expanduser()
        self._revocation_persistent = False
        self._revocation_persistent = self._init_revoked_store()
        if self._revocation_persistent:
            with self._revoked_lock:
                self._cleanup_revoked_locked()
                self._persist_revoked_locked()

    def issue_access_token(self, subject: str, role: str) -> str:
        """Выпуск access-токена."""
        return self._issue(subject, role, "access", self._access_ttl)

    def issue_refresh_token(self, subject: str, role: str) -> str:
        """Выпуск refresh-токена."""
        return self._issue(subject, role, "refresh", self._refresh_ttl)

    def issue_token_pair(self, subject: str, role: str) -> dict[str, str | int]:
        """Выпуск пары access + refresh токенов."""
        return {
            "access_token": self.issue_access_token(subject, role),
            "refresh_token": self.issue_refresh_token(subject, role),
            "token_type": "Bearer",
            "expires_in": self._access_ttl,
        }

    def validate(self, token: str) -> Optional[TokenClaims]:
        """
        Валидация и декодирование JWT-токена.

        Возвращает None при невалидном/просроченном/отозванном токене.
        """
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[_ALGORITHM],
                issuer=_ISSUER,
                options={
                    "require": ["sub", "role", "exp", "iat", "jti", "token_type"],
                    "verify_exp": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError:
            logger.debug("JWT expired")
            return None
        except jwt.InvalidTokenError as exc:
            logger.debug("JWT invalid: %s", exc)
            return None

        jti = str(payload.get("jti", ""))
        with self._revoked_lock:
            if jti in self._revoked_jti:
                logger.warning("JWT revoked jti=%s", jti)
                return None
            # Периодическая очистка протухших JTI
            if len(self._revoked_jti) > self._max_revoked:
                self._cleanup_revoked_locked()

        return TokenClaims(
            sub=str(payload["sub"]),
            role=str(payload["role"]).strip().lower() or "viewer",
            token_type=str(payload["token_type"]),
            exp=int(payload["exp"]),
            iat=int(payload["iat"]),
            jti=jti,
        )

    def refresh(self, refresh_token: str) -> Optional[dict[str, str | int]]:
        """
        Обновление токенов по refresh-токену.

        Старый refresh-токен отзывается после успешного обновления.
        """
        claims = self.validate(refresh_token)
        if claims is None:
            return None
        if claims.token_type != "refresh":
            logger.warning("Refresh attempt with non-refresh token")
            return None
        # Отзываем использованный refresh-токен (rotation)
        with self._revoked_lock:
            self._revoked_jti[claims.jti] = time.time()
            if len(self._revoked_jti) > self._max_revoked:
                self._cleanup_revoked_locked()
            self._persist_revoked_locked()
        return self.issue_token_pair(claims.sub, claims.role)

    def revoke(self, jti: str) -> None:
        """Отзыв токена по jti."""
        with self._revoked_lock:
            self._revoked_jti[jti] = time.time()
            if len(self._revoked_jti) > self._max_revoked:
                self._cleanup_revoked_locked()
            self._persist_revoked_locked()

    def _cleanup_revoked_locked(self) -> None:
        """Очистка протухших JTI (старше максимального TTL)."""
        max_ttl = max(self._access_ttl, self._refresh_ttl)
        cutoff = time.time() - max_ttl * 2
        expired = [jti for jti, ts in self._revoked_jti.items() if ts < cutoff]
        for jti in expired:
            del self._revoked_jti[jti]
        if expired:
            self._persist_revoked_locked()

    def _init_revoked_store(self) -> bool:
        """Подгружает revoked JTI из файла и подготавливает persistent store."""
        try:
            self._revoked_store_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning(
                "JWT revocation store is unavailable (%s): %s. Falling back to in-memory mode.",
                self._revoked_store_path,
                exc,
            )
            return False

        if self._revoked_store_path.exists():
            try:
                raw = json.loads(self._revoked_store_path.read_text(encoding="utf-8"))
                bucket = raw.get("revoked_jti", raw) if isinstance(raw, dict) else {}
                if isinstance(bucket, dict):
                    for jti, ts in bucket.items():
                        try:
                            self._revoked_jti[str(jti)] = float(ts)
                        except (TypeError, ValueError):
                            continue
            except Exception as exc:
                logger.warning("Failed to load JWT revocation store: %s", exc)

        return True

    def _persist_revoked_locked(self) -> None:
        if not self._revocation_persistent:
            return
        payload = {
            "revoked_jti": self._revoked_jti,
            "updated_at": int(time.time()),
        }
        tmp_path = self._revoked_store_path.with_suffix(
            self._revoked_store_path.suffix + ".tmp"
        )
        try:
            tmp_path.write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )
            os.replace(tmp_path, self._revoked_store_path)
        except Exception as exc:
            logger.warning("Failed to persist JWT revocation store: %s", exc)
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    def _issue(self, subject: str, role: str, token_type: str, ttl: int) -> str:
        now = int(time.time())
        # M1 fix: используем полный hexdigest (64 символа) вместо усечённого до 24
        jti = hashlib.sha256(
            f"{subject}:{role}:{token_type}:{now}:{os.urandom(16).hex()}".encode()
        ).hexdigest()
        payload: dict[str, Any] = {
            "sub": subject,
            "role": role,
            "token_type": token_type,
            "iss": _ISSUER,
            "iat": now,
            "exp": now + ttl,
            "jti": jti,
        }
        return jwt.encode(payload, self._secret, algorithm=_ALGORITHM)


def get_jwt_provider(
    secret: str | None = None,
    access_ttl: int | None = None,
    refresh_ttl: int | None = None,
    revoked_store_path: str | None = None,
) -> Optional[JWTProvider]:
    """
    Фабрика JWTProvider. Возвращает None если секрет не задан.
    """
    secret = secret or os.getenv("PHANTOM_JWT_SECRET", "").strip()
    if not secret or len(secret) < _MIN_SECRET_LENGTH:
        return None
    kwargs: dict[str, Any] = {"secret": secret}
    if access_ttl is not None:
        kwargs["access_ttl"] = access_ttl
    if refresh_ttl is not None:
        kwargs["refresh_ttl"] = refresh_ttl
    if revoked_store_path is not None:
        kwargs["revoked_store_path"] = revoked_store_path
    try:
        return JWTProvider(**kwargs)
    except ValueError as exc:
        logger.error("JWT provider init failed: %s", exc)
        return None
