package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	templates *template.Template
	db        *sql.DB
	store     = sessions.NewCookieStore([]byte("secret-key"))
)

type PageData struct {
	RegisterErrorMessage   string
	RegisterSuccessMessage string
	LoginErrorMessage      string
	LoginSuccessMessage    string
	Username               string
}

// Добавим новые структуры
type Topic struct {
	ID           int
	Title        string
	Content      string
	Author       string
	CreatedAt    string
	Likes        int
	Dislikes     int
	UserReaction int // 1 для лайка, -1 для дизлайка, 0 для отсутствия реакции
}

type Comment struct {
	ID           int
	TopicID      int
	Content      string
	Author       string
	CreatedAt    string
	Likes        int
	Dislikes     int
	UserReaction int
}

type ProfileData struct {
	Username      string
	TopicsCount   int
	CommentsCount int
	RecentTopics  []Topic
	Reputation    int
}

type ProfileComment struct {
	ID        int
	Content   string
	Author    string
	CreatedAt string
}

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600 * 24, // 24 часа
		HttpOnly: true,      // Защита от XSS
	}

	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal("Failed to parse templates:", err)
	}
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func InitDB() {
	// Открываем базу данных
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Создаем таблицы
	sqlStmt := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS topics (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        author TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        topic_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        author TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (topic_id) REFERENCES topics (id)
    );

    CREATE TABLE IF NOT EXISTS profile_comments (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        profile_username TEXT NOT NULL,
        content TEXT NOT NULL,
        author TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (profile_username) REFERENCES users(username),
        FOREIGN KEY (author) REFERENCES users(username)
    );

    CREATE TABLE IF NOT EXISTS reactions (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        target_type TEXT NOT NULL,  -- 'topic' или 'comment'
        target_id INTEGER NOT NULL,
        reaction_type INTEGER NOT NULL,  -- 1 для лайка, -1 для дизлайка
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(username),
        UNIQUE(user_id, target_type, target_id)
    );
    `
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("%q: %s\n", err, sqlStmt)
	}

	log.Println("База данных создана успешно")
}

func getUsernameFromSession(r *http.Request) string {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Session error: %v", err)
		return ""
	}

	if username, ok := session.Values["username"].(string); ok {
		return username
	}
	return ""
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if username := getUsernameFromSession(r); username != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if len(password) < 6 {
			renderTemplate(w, "register", PageData{RegisterErrorMessage: "Пароль должен быть не менее 6 символов"})
			return
		}

		if len(username) < 3 {
			renderTemplate(w, "register", PageData{RegisterErrorMessage: "Логин должен быть не менее 3 символов"})
			return
		}

		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
		if err != nil {
			log.Println("Failed to check if username exists:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if exists {
			renderTemplate(w, "register", PageData{RegisterErrorMessage: "Пользователь с таким именем уже существует."})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Ошибка при шифровании пароля", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec(`
			INSERT INTO users (username, password) 
			VALUES (?, ?)
		`, username, hashedPassword)
		if err != nil {
			http.Error(w, "Ошибка при сохранении пользователя", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else {
		renderTemplate(w, "register", nil)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if username := getUsernameFromSession(r); username != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var storedHashedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHashedPassword)
		if err == sql.ErrNoRows {
			renderTemplate(w, "login", PageData{LoginErrorMessage: "Аккаунт не существует"})
			return
		} else if err != nil {
			log.Printf("Database error: %v", err)
			http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password))
		if err != nil {
			renderTemplate(w, "login", PageData{LoginErrorMessage: "Неверный пароль"})
			return
		}

		session, err := store.Get(r, "session-name")
		if err != nil {
			log.Printf("Session error: %v", err)
			http.Error(w, "Ошибка сессии", http.StatusInternalServerError)
			return
		}

		session.Values["username"] = username
		if err := session.Save(r, w); err != nil {
			log.Printf("Session save error: %v", err)
			http.Error(w, "Ошибка сохранения сессии", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		renderTemplate(w, "login", nil)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	if err := clearSession(w, r); err != nil {
		log.Printf("Logout error: %v", err)
		http.Error(w, "Ошибка при выходе", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Добавляем функцию для безопасного завершения сессии
func clearSession(w http.ResponseWriter, r *http.Request) error {
	session, err := store.Get(r, "session-name")
	if err != nil {
		return err
	}

	// Очищаем все значения
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1

	return session.Save(r, w)
}

// Добавим новые обработчики
func createTopicHandler(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromSession(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		title := r.FormValue("title")
		content := r.FormValue("content")

		_, err := db.Exec("INSERT INTO topics (title, content, author) VALUES (?, ?, ?)",
			title, content, username)
		if err != nil {
			http.Error(w, "Ошибка при создании темы", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		renderTemplate(w, "create_topic", PageData{Username: username})
	}
}

func topicHandler(w http.ResponseWriter, r *http.Request) {
	username := getUsernameFromSession(r)
	topicID := r.URL.Query().Get("id")

	if r.Method == http.MethodPost {
		if username == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		content := r.FormValue("content")
		_, err := db.Exec("INSERT INTO comments (topic_id, content, author) VALUES (?, ?, ?)",
			topicID, content, username)
		if err != nil {
			http.Error(w, "Ошибка при добавлении комментария", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/topic?id="+topicID, http.StatusSeeOther)
		return
	}

	var topic Topic
	err := db.QueryRow("SELECT id, title, content, author, created_at FROM topics WHERE id = ?", topicID).
		Scan(&topic.ID, &topic.Title, &topic.Content, &topic.Author, &topic.CreatedAt)
	if err != nil {
		http.Error(w, "Тема не найдена", http.StatusNotFound)
		return
	}

	rows, err := db.Query("SELECT id, content, author, created_at FROM comments WHERE topic_id = ? ORDER BY created_at", topicID)
	if err != nil {
		http.Error(w, "Ошибка при загрузке комментариев", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		err := rows.Scan(&comment.ID, &comment.Content, &comment.Author, &comment.CreatedAt)
		if err != nil {
			continue
		}
		comments = append(comments, comment)
	}

	// Получаем рейтинг темы и реакцию пользователя
	err = db.QueryRow(`
		SELECT 
			(SELECT COUNT(*) FROM reactions WHERE target_type = 'topic' AND target_id = ? AND reaction_type = 1),
			(SELECT COUNT(*) FROM reactions WHERE target_type = 'topic' AND target_id = ? AND reaction_type = -1),
			COALESCE((SELECT reaction_type FROM reactions WHERE target_type = 'topic' AND target_id = ? AND user_id = ?), 0)
	`, topicID, topicID, topicID, username).Scan(&topic.Likes, &topic.Dislikes, &topic.UserReaction)

	// Получаем рейтинг для каждого комментария
	for i := range comments {
		db.QueryRow(`
			SELECT 
				(SELECT COUNT(*) FROM reactions WHERE target_type = 'comment' AND target_id = ? AND reaction_type = 1),
				(SELECT COUNT(*) FROM reactions WHERE target_type = 'comment' AND target_id = ? AND reaction_type = -1),
				COALESCE((SELECT reaction_type FROM reactions WHERE target_type = 'comment' AND target_id = ? AND user_id = ?), 0)
		`, comments[i].ID, comments[i].ID, comments[i].ID, username).Scan(
			&comments[i].Likes, &comments[i].Dislikes, &comments[i].UserReaction)
	}

	data := struct {
		PageData
		Topic    Topic
		Comments []Comment
	}{
		PageData: PageData{Username: username},
		Topic:    topic,
		Comments: comments,
	}

	renderTemplate(w, "topic", data)
}

// Добавим обработчик профиля
func profileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Path[len("/profile/"):]

	var profileData ProfileData
	err := db.QueryRow(`
		SELECT username,
		(SELECT COUNT(*) FROM topics WHERE author = users.username),
		(SELECT COUNT(*) FROM comments WHERE author = users.username)
		FROM users WHERE username = ?
	`, username).Scan(&profileData.Username, &profileData.TopicsCount, &profileData.CommentsCount)

	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusNotFound)
		return
	}

	// Получаем последние темы пользователя
	rows, err := db.Query(`
		SELECT id, title, created_at 
		FROM topics 
		WHERE author = ? 
		ORDER BY created_at DESC LIMIT 5
	`, username)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var topic Topic
			if err := rows.Scan(&topic.ID, &topic.Title, &topic.CreatedAt); err == nil {
				profileData.RecentTopics = append(profileData.RecentTopics, topic)
			}
		}
	}

	// Получаем комментарии к профилю
	rows, err = db.Query(`
		SELECT id, content, author, created_at 
		FROM profile_comments 
		WHERE profile_username = ? 
		ORDER BY created_at DESC
	`, username)

	var profileComments []ProfileComment
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var comment ProfileComment
			if err := rows.Scan(&comment.ID, &comment.Content, &comment.Author, &comment.CreatedAt); err == nil {
				profileComments = append(profileComments, comment)
			}
		}
	}

	// Получаем общую репутацию пользователя
	err = db.QueryRow(`
		SELECT 
			COALESCE(
				(SELECT SUM(CASE WHEN r.reaction_type = 1 THEN 1 ELSE -1 END)
				FROM reactions r
				WHERE (r.target_type = 'topic' AND r.target_id IN (SELECT id FROM topics WHERE author = ?))
				OR (r.target_type = 'comment' AND r.target_id IN (SELECT id FROM comments WHERE author = ?))
				), 0)
	`, username, username).Scan(&profileData.Reputation)

	data := struct {
		PageData
		ProfileData     ProfileData
		ProfileComments []ProfileComment
	}{
		PageData:        PageData{Username: getUsernameFromSession(r)},
		ProfileData:     profileData,
		ProfileComments: profileComments,
	}

	renderTemplate(w, "profile", data)
}

// Добавим обработчик комментариев к профилю
func addProfileCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	username := getUsernameFromSession(r)
	if username == "" {
		http.Error(w, "Необходима авторизация", http.StatusUnauthorized)
		return
	}

	profileUsername := r.URL.Path[len("/profile/") : len(r.URL.Path)-len("/comment")]
	content := r.FormValue("content")

	_, err := db.Exec(`
		INSERT INTO profile_comments (profile_username, content, author) 
		VALUES (?, ?, ?)
	`, profileUsername, content, username)

	if err != nil {
		http.Error(w, "Ошибка при добавлении комментария", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/profile/"+profileUsername, http.StatusSeeOther)
}

func handleReaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	username := getUsernameFromSession(r)
	if username == "" {
		http.Error(w, "Необходима авторизация", http.StatusUnauthorized)
		return
	}

	targetType := r.FormValue("type")       // "topic" или "comment"
	targetID := r.FormValue("id")           // ID темы или комментария
	reactionType := r.FormValue("reaction") // "1" для лайка, "-1" для дизлайка

	// Удаляем существующую реакцию
	_, err := db.Exec(`
		DELETE FROM reactions 
		WHERE user_id = ? AND target_type = ? AND target_id = ?
	`, username, targetType, targetID)
	if err != nil {
		http.Error(w, "Ошибка при обновлении реакции", http.StatusInternalServerError)
		return
	}

	// Добавляем новую реакцию
	_, err = db.Exec(`
		INSERT INTO reactions (user_id, target_type, target_id, reaction_type)
		VALUES (?, ?, ?, ?)
	`, username, targetType, targetID, reactionType)
	if err != nil {
		http.Error(w, "Ошибка при сохранении реакции", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	var err error
	InitDB()

	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Затем регистрируем остальные обработчики
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/create-topic", createTopicHandler)
	http.HandleFunc("/topic", topicHandler)
	http.HandleFunc("/news", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "7news", PageData{Username: getUsernameFromSession(r)})
	})
	http.HandleFunc("/support", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			PageData
			Success bool
		}{
			PageData: PageData{Username: getUsernameFromSession(r)},
			Success:  r.URL.Query().Get("success") == "true",
		}
		renderTemplate(w, "10support", data)
	})

	// Корневой обработчик регистрируем последним
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		rows, err := db.Query("SELECT id, title, author, created_at FROM topics ORDER BY created_at DESC")
		if err != nil {
			http.Error(w, "Ошибка при загрузке тем", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var topics []Topic
		for rows.Next() {
			var topic Topic
			err := rows.Scan(&topic.ID, &topic.Title, &topic.Author, &topic.CreatedAt)
			if err != nil {
				continue
			}
			topics = append(topics, topic)
		}

		data := struct {
			PageData
			Topics []Topic
		}{
			PageData: PageData{Username: getUsernameFromSession(r)},
			Topics:   topics,
		}

		renderTemplate(w, "1index", data)
	})

	http.HandleFunc("/profile/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/comment") {
			addProfileCommentHandler(w, r)
			return
		}
		profileHandler(w, r)
	})

	// Обслуживание статических файлов
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/reaction", handleReaction)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	log.Printf("Сервер запущен на порту %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
