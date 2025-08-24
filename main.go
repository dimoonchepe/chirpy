package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dimoonchepe/chirpy/internal/auth"
	"github.com/dimoonchepe/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	queries        *database.Queries
	secret         string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

type ChirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func handlerHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	html := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	w.Write([]byte(html))
}

func (cfg *apiConfig) handlerAddUser(w http.ResponseWriter, r *http.Request) {
	type user struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	w.Header().Set("Content-Type", "application/json")
	var u user
	err := decoder.Decode(&u)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid cuser")
		return
	}
	if len(u.Email) < 1 {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}
	hashedPassword, err := auth.HashPassword(u.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to hash password")
		return
	}
	dbUser, err := cfg.queries.CreateUser(r.Context(), database.CreateUserParams{Email: u.Email, HashedPassword: hashedPassword})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}
	resUser := User{
		ID:          dbUser.ID,
		Email:       dbUser.Email,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		IsChirpyRed: dbUser.IsChirpyRed,
	}
	respondWithJSON(w, http.StatusCreated, resUser)
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID, errStr := cfg.validateJWT(r.Header)
	if errStr != "" {
		respondWithError(w, http.StatusUnauthorized, errStr)
		return
	}
	type UpdateUser struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var u UpdateUser
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&u)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user")
		return
	}
	if len(u.Email) < 1 {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}
	if len(u.Password) < 1 {
		respondWithError(w, http.StatusBadRequest, "Password is required")
		return
	}
	hashedPassword, err := auth.HashPassword(u.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to hash password")
		return
	}
	dbUser, err := cfg.queries.UpdateUser(r.Context(), database.UpdateUserParams{ID: userID, Email: u.Email, HashedPassword: hashedPassword})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}
	resUser := User{
		ID:          dbUser.ID,
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
	}
	respondWithJSON(w, http.StatusOK, resUser)
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type login struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	w.Header().Set("Content-Type", "application/json")
	var l login
	err := decoder.Decode(&l)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid login")
		return
	}
	if len(l.Email) < 1 {
		respondWithError(w, http.StatusBadRequest, "Email is required")
		return
	}
	if len(l.Password) < 1 {
		respondWithError(w, http.StatusBadRequest, "Password is required")
		return
	}
	dbUser, err := cfg.queries.GetUserByEmail(r.Context(), l.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}
	err = auth.CheckPasswordHash(l.Password, dbUser.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid email or password")
		return
	}
	token, err := auth.MakeJWT(dbUser.ID, cfg.secret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate refresh token")
		return
	}
	cfg.queries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:  refreshToken,
		UserID: dbUser.ID,
	})
	resUser := User{
		ID:           dbUser.ID,
		Email:        dbUser.Email,
		IsChirpyRed:  dbUser.IsChirpyRed,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Token:        token,
		RefreshToken: refreshToken,
	}
	respondWithJSON(w, http.StatusOK, resUser)
}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil || refreshToken == "" {
		respondWithError(w, http.StatusUnauthorized, "Invalid token (GetBearerToken failed)")
		return
	}
	userId, err := cfg.queries.GetUserIdFromRefreshToken(r.Context(), refreshToken)
	if err != nil || userId == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token (No valid refresh token found)")
		return
	}
	token, err := auth.MakeJWT(userId, cfg.secret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}
	type RefreshResponse struct {
		Token string `json:"token"`
	}
	respondWithJSON(w, http.StatusOK, RefreshResponse{Token: token})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil || refreshToken == "" {
		respondWithError(w, http.StatusUnauthorized, "Invalid token (GetBearerToken failed)")
		return
	}
	err = cfg.queries.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to revoke token")
		return
	}
	respondWithJSON(w, http.StatusNoContent, nil)
}

func (cfg *apiConfig) validateJWT(header http.Header) (uuid.UUID, string) {
	token, err := auth.GetBearerToken(header)
	if err != nil {
		return uuid.Nil, "Invalid token (GetBearerToken failed)"
	}
	userID, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		return uuid.Nil, "Invalid token (ValidateJWT failed)"
	}
	if userID == uuid.Nil {
		return uuid.Nil, "Invalid token (UserID is nil)"
	}
	return userID, ""
}

func (cfg *apiConfig) handlerAddChirp(w http.ResponseWriter, r *http.Request) {
	userID, errStr := cfg.validateJWT(r.Header)
	if errStr != "" {
		respondWithError(w, http.StatusUnauthorized, errStr)
		return
	}
	type chirp struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	w.Header().Set("Content-Type", "application/json")
	var c chirp
	err := decoder.Decode(&c)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp")
		return
	}
	if len(c.Body) < 1 {
		respondWithError(w, http.StatusBadRequest, "Content is required")
		return
	}
	if len(c.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Fields(c.Body)
	for i, word := range words {
		// if word.ToLower in badwrds replace it with "****"
		if slices.Contains(badWords, strings.ToLower(word)) {
			words[i] = "****"
		}
	}
	body := strings.Join(words, " ")
	dbChirp, err := cfg.queries.CreateChirp(r.Context(), database.CreateChirpParams{Body: body, UserID: userID})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to create chirp")
		return
	}
	resChirp := ChirpResponse{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}
	respondWithJSON(w, http.StatusCreated, resChirp)
}

func (cfg *apiConfig) handlerGetAllChirps(w http.ResponseWriter, r *http.Request) {
	authorID := r.URL.Query().Get("author_id")
	sortDirection := r.URL.Query().Get("sort")
	var dbChirps []database.Chirp
	if authorID != "" {
		authorUID, err := uuid.Parse(authorID)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid author ID")
			return
		}
		dbChirps, err = cfg.queries.GetAllChirpsByAuthorID(r.Context(), authorUID)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to get chirps")
			return
		}
	} else {
		var err error
		dbChirps, err = cfg.queries.GetAllChirps(r.Context())
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to get chirps")
			return
		}
	}
	switch sortDirection {
	case "desc":
		sort.Slice(dbChirps, func(i, j int) bool {
			return dbChirps[i].CreatedAt.After(dbChirps[j].CreatedAt)
		})
	case "asc":
		sort.Slice(dbChirps, func(i, j int) bool {
			return dbChirps[i].CreatedAt.Before(dbChirps[j].CreatedAt)
		})
	}
	resChirps := make([]ChirpResponse, len(dbChirps))
	for i, dbChirp := range dbChirps {
		resChirps[i] = ChirpResponse{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		}
	}
	respondWithJSON(w, http.StatusOK, resChirps)
}

func (cfg *apiConfig) handlerGetChirp(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}
	dbChirp, err := cfg.queries.GetChirp(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
		} else {
			respondWithError(w, http.StatusInternalServerError, "Failed to get chirp")
		}
		return
	}
	resChirp := ChirpResponse{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}
	respondWithJSON(w, http.StatusOK, resChirp)
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	userID, errStr := cfg.validateJWT(r.Header)
	if errStr != "" {
		respondWithError(w, http.StatusUnauthorized, errStr)
		return
	}
	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}
	dbChirp, err := cfg.queries.GetChirp(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Chirp not found")
		} else {
			respondWithError(w, http.StatusInternalServerError, "Failed to get chirp")
		}
		return
	}
	if dbChirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}
	err = cfg.queries.DeleteChirp(r.Context(), id)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to delete chirp")
		return
	}
	respondWithJSON(w, http.StatusNoContent, nil)
}

func (cfg *apiConfig) handlerPolkaWebhook(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetApiKey(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}
	polkaKey := os.Getenv("POLKA_KEY")
	if apiKey != polkaKey {
		respondWithError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}
	var payload struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}
	err = json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}
	if payload.Event != "user.upgraded" {
		respondWithJSON(w, http.StatusNoContent, nil)
		return
	}
	if payload.Data.UserID == uuid.Nil {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	dbUser, err := cfg.queries.GetUserByID(r.Context(), payload.Data.UserID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "User not found")
		return
	}
	err = cfg.queries.UpgradeUserToRed(r.Context(), dbUser.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to upgrade user")
		return
	}
	respondWithJSON(w, http.StatusNoContent, nil)
}
func respondWithJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondWithError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	platform := os.Getenv("PLATFORM")
	if platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}
	cfg.fileserverHits.Store(0)
	cfg.queries.DeleteAllUsers(r.Context())

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Fileserver Hits: %d\n", cfg.fileserverHits.Load())
}

func main() {
	godotenv.Load()
	apiCfg := &apiConfig{}

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)
	apiCfg.queries = dbQueries
	apiCfg.secret = os.Getenv("SECRET")

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", handlerHealthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.reset)
	mux.HandleFunc("POST /api/users", apiCfg.handlerAddUser)
	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateUser)
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerAddChirp)
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDeleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerPolkaWebhook)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fmt.Println("Starting server on port 8080...")
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
