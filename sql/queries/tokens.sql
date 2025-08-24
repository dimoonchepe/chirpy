-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (token, user_id, expires_at)
VALUES (
    $1, $2, now() + interval '60 days'
);

-- name: GetUserIdFromRefreshToken :one
SELECT user_id FROM refresh_tokens
WHERE token = $1 AND expires_at > now() AND revoked_at IS NULL;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET
revoked_at = now(),
updated_at = now()
WHERE token = $1;
