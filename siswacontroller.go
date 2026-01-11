package controllers

import (
	"belajar_golang/database"
	"belajar_golang/models"
	"net/http"
	"text/template"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// Deklarasi store session untuk login siswa
var store = sessions.NewCookieStore([]byte("secret-key-rahasia"))

// ======================== LOGIN ========================
func Halamanlogin(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("views/login.html"))
	tmpl.Execute(w, nil)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Ambil data siswa dari database
	var user models.Siswa
	err := database.DB.QueryRow("SELECT id, username, password FROM siswa WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Cek password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Simpan session login
	session, _ := store.Get(r, "session")
	session.Values["username"] = user.Username
	session.Save(r, w)

	http.Redirect(w, r, "/dasboard", http.StatusSeeOther)
}

// ======================== DASHBOARD ========================
func Dasboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// ===== Ambil data dari tabel nama_siswa =====
	rows, err := database.DB.Query(`
		SELECT id, nama, kelas, jenis_kelamin, hari_jadwal, kehadiran
		FROM nama_siswa`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var namaSiswaList []models.Nama_siswa
	for rows.Next() {
		var s models.Nama_siswa
		rows.Scan(&s.ID, &s.Nama, &s.Kelas, &s.Jenis_Kelamin, &s.Hari_Jadwal, &s.Kehadiran)
		namaSiswaList = append(namaSiswaList, s)
	}

	// ===== Ambil data dari tabel mapel =====
	mapelRows, err := database.DB.Query(`
		SELECT id, mata_pelajaran, guru_pengajar, kehadiran_guru
		FROM mapel`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer mapelRows.Close()

	var mapelList []models.Mapel
	for mapelRows.Next() {
		var m models.Mapel
		mapelRows.Scan(&m.ID, &m.Mata_pelajaran, &m.Guru_pengajar, &m.Kehadiran_guru)
		mapelList = append(mapelList, m)
	}

	// Kirim semua data ke template
	tmpl := template.Must(template.ParseFiles("views/dasboard.html"))
	tmpl.Execute(w, map[string]interface{}{
		"Username":   username,
		"Nama_siswa": namaSiswaList,
		"Mapel":      mapelList,
	})
}

// ======================== ABSENSI SISWA ========================
func Absensi_siswa(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/dasboard", http.StatusSeeOther)
		return
	}

	// Ambil data dari form
	nama := r.FormValue("nama")
	kelas := r.FormValue("kelas")
	jenisKelamin := r.FormValue("jenis_kelamin")
	hariJadwal := r.FormValue("hari_jadwal")
	kehadiran := r.FormValue("kehadiran")

	// Ambil session untuk tahu siapa yang login
	session, _ := store.Get(r, "session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Ambil ID siswa dari tabel siswa
	var siswaID int
	err := database.DB.QueryRow("SELECT id FROM siswa WHERE username = ?", username).Scan(&siswaID)
	if err != nil {
		http.Error(w, "Siswa tidak ditemukan", http.StatusInternalServerError)
		return
	}

	var adminID interface{} = nil

	// Simpan ke tabel nama_siswa
	_, err = database.DB.Exec(`
		INSERT INTO nama_siswa (siswa_id, admin_id, nama, kelas, jenis_kelamin, hari_jadwal, kehadiran)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		siswaID, adminID, nama, kelas, jenisKelamin, hariJadwal, kehadiran)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dasboard", http.StatusSeeOther)
}

// ======================== ABSENSI GURU / MAPEL ========================
func Mapel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/dasboard", http.StatusSeeOther)
		return
	}

	// Ambil data dari form mapel
	mataPelajaran := r.FormValue("mata_pelajaran")
	guruPengajar := r.FormValue("guru_pengajar")
	kehadiranGuru := r.FormValue("kehadiran_guru")

	// Ambil session login
	session, _ := store.Get(r, "session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Ambil ID siswa berdasarkan username
	var siswaID int
	err := database.DB.QueryRow("SELECT id FROM siswa WHERE username = ?", username).Scan(&siswaID)
	if err != nil {
		http.Error(w, "Siswa tidak ditemukan", http.StatusInternalServerError)
		return
	}

	// Ambil ID dari tabel nama_siswa yang paling baru
	var namaSiswaID int
	err = database.DB.QueryRow(`
		SELECT id FROM nama_siswa WHERE siswa_id = ? ORDER BY id DESC LIMIT 1`, siswaID).Scan(&namaSiswaID)
	if err != nil {
		http.Error(w, "Data absensi siswa tidak ditemukan", http.StatusInternalServerError)
		return
	}

	// Simpan ke tabel mapel
	_, err = database.DB.Exec(`
		INSERT INTO mapel (nama_siswa_id, mata_pelajaran, guru_pengajar, kehadiran_guru)
		VALUES (?, ?, ?, ?)`,
		namaSiswaID, mataPelajaran, guruPengajar, kehadiranGuru)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dasboard", http.StatusSeeOther)
}
