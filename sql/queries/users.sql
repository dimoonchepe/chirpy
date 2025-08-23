-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid (), now(), now(), $1, $2
)
RETURNING id, created_at, updated_at, email;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password FROM users WHERE email = $1;

-- name: UpdateUser :one
UPDATE users SET
email = $2,
hashed_password = $3,
updated_at = now()
WHERE id = $1
RETURNING id, created_at, updated_at, email;

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
