-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid (), now(), now(), $1, $2
)
RETURNING id, created_at, updated_at, is_chirpy_red, email;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT id, created_at, updated_at, email, is_chirpy_red FROM users WHERE id = $1;

-- name: UpdateUser :one
UPDATE users SET
email = $2,
hashed_password = $3,
updated_at = now()
WHERE id = $1
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: UpgradeUserToRed :exec
UPDATE users SET is_chirpy_red = TRUE, updated_at = now() WHERE id = $1;
