package controllers

import (
	"belajar_golang/database"
	"belajar_golang/models"
	"fmt"
	"net/http"
	"text/template"

	"github.com/gorilla/sessions"
	"github.com/xuri/excelize/v2"
	"golang.org/x/crypto/bcrypt"
)

var Tempat = sessions.NewCookieStore([]byte("secret-key-rahasia-admin"))

// ================= LOGIN ADMIN =================
func HalamanLoginAdmin(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("views/admin/login_admin.html"))
	tmpl.Execute(w, nil)
}

func ProsesLoginAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var admin models.Admin
	err := database.DB.QueryRow(`
		SELECT id, username, password FROM admin WHERE username = ?`, username).
		Scan(&admin.ID, &admin.Username, &admin.Password)
	if err != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password))
	if err != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	session, _ := Tempat.Get(r, "session_admin")
	session.Values["admin_username"] = admin.Username
	session.Save(r, w)

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// ================= DASHBOARD ADMIN =================
func AdminDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := Tempat.Get(r, "session_admin")
	username, ok := session.Values["admin_username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	// ====== Ambil data siswa ======
	rowsSiswa, err := database.DB.Query(`
		SELECT id, nama, kelas, jenis_kelamin, hari_jadwal, kehadiran
		FROM nama_siswa`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rowsSiswa.Close()

	var namaSiswaList []models.Nama_siswa
	for rowsSiswa.Next() {
		var s models.Nama_siswa
		if err := rowsSiswa.Scan(
			&s.ID, &s.Nama, &s.Kelas, &s.Jenis_Kelamin, &s.Hari_Jadwal, &s.Kehadiran,
		); err == nil {
			namaSiswaList = append(namaSiswaList, s)
		}
	}

	// ====== Ambil data guru/mapel ======
	rowsGuru, err := database.DB.Query(`
		SELECT id, mata_pelajaran, guru_pengajar, kehadiran_guru
		FROM mapel`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rowsGuru.Close()

	var mapelList []models.Mapel
	for rowsGuru.Next() {
		var g models.Mapel
		if err := rowsGuru.Scan(
			&g.ID, &g.Mata_pelajaran, &g.Guru_pengajar, &g.Kehadiran_guru,
		); err == nil {
			mapelList = append(mapelList, g)
		}
	}

	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}

	tmpl := template.Must(template.New("admin_dashboard.html").
		Funcs(funcMap).
		ParseFiles("views/admin/admin_dashboard.html"))

	tmpl.Execute(w, map[string]interface{}{
		"Username":   username,
		"Nama_siswa": namaSiswaList,
		"Mapel":      mapelList,
	})
}

// ================= LOGOUT ADMIN =================
func LogoutAdmin(w http.ResponseWriter, r *http.Request) {
	session, _ := Tempat.Get(r, "session_admin")
	delete(session.Values, "admin_username")
	session.Save(r, w)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// ================= UPDATE KEHADIRAN SISWA =================
func UpdateKehadiranSiswa(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}

	id := r.FormValue("id")
	kehadiran := r.FormValue("kehadiran")

	_, err := database.DB.Exec("UPDATE nama_siswa SET kehadiran = ? WHERE id = ?", kehadiran, id)
	if err != nil {
		http.Error(w, "Gagal update kehadiran siswa", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// ================= UPDATE KEHADIRAN GURU =================
func UpdateKehadiranGuru(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}

	id := r.FormValue("id")
	kehadiran := r.FormValue("kehadiran")

	_, err := database.DB.Exec("UPDATE mapel SET kehadiran_guru = ? WHERE id = ?", kehadiran, id)
	if err != nil {
		http.Error(w, "Gagal update kehadiran guru", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// ================= EXPORT KE EXCEL SISWA =================
func InputExcelbagianSiswa(w http.ResponseWriter, r *http.Request) {
	// SELECT TO DATA SISWA
	kolom_siswa, input_ke_percabangan := database.DB.Query("SELECT nama, kelas, jenis_kelamin, hari_jadwal, kehadiran FROM nama_siswa")
	if input_ke_percabangan != nil {
		http.Error(w, "GAGAL AMBIL DATA", http.StatusInternalServerError)
		return
	}
	defer kolom_siswa.Close()

	// AMBIL DATA SISWA  DARI SELECT => KE excelize EXCEL
	siswa_sekolah := excelize.NewFile()
	sheet := "Data Siswa"
	siswa_sekolah.NewSheet(sheet)
	siswa_sekolah.SetCellValue(sheet, "A1", "Nama") // kolom data pada SQL FORM siswa
	siswa_sekolah.SetCellValue(sheet, "B1", "Kelas")
	siswa_sekolah.SetCellValue(sheet, "C1", "Jenis Kelamin")
	siswa_sekolah.SetCellValue(sheet, "D1", "Hari/Jadwal")
	siswa_sekolah.SetCellValue(sheet, "E1", "Kehadiran")
	// loop for  untuk nampilin perulangan data di sql
	INPUTSISWA := 2
	for kolom_siswa.Next() {
		// deklarasi data
		var nama, kelas, jadwalkelas, hari, kehadiran string
		kolom_siswa.Scan(&nama, &kelas, &jadwalkelas, &hari, &kehadiran)
		siswa_sekolah.SetCellValue(sheet, fmt.Sprintf("A%d", INPUTSISWA), nama)
		siswa_sekolah.SetCellValue(sheet, fmt.Sprintf("B%d", INPUTSISWA), kelas)
		siswa_sekolah.SetCellValue(sheet, fmt.Sprintf("C%d", INPUTSISWA), jadwalkelas)
		siswa_sekolah.SetCellValue(sheet, fmt.Sprintf("D%d", INPUTSISWA), hari)
		siswa_sekolah.SetCellValue(sheet, fmt.Sprintf("E%d", INPUTSISWA), kehadiran)
		INPUTSISWA++
	}

	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename="data_siswa.xlsx"`)
	siswa_sekolah.Write(w)
}

// ================= EXPORT KE EXCEL GURU =================
func InputExcelGuru(guru http.ResponseWriter, r *http.Request) {
	kolom_guru, input_ke_if := database.DB.Query("SELECT mata_pelajaran, guru_pengajar, kehadiran_guru FROM mapel")
	if input_ke_if != nil {
		http.Error(guru, "Gagal ambil data guru", http.StatusInternalServerError)
		return
	}
	defer kolom_guru.Close()

	guru_sekolah := excelize.NewFile()
	sheet := "Data Guru"
	guru_sekolah.NewSheet(sheet)
	guru_sekolah.SetCellValue(sheet, "A1", "Mata Pelajaran")
	guru_sekolah.SetCellValue(sheet, "B1", "Guru Pengajar")
	guru_sekolah.SetCellValue(sheet, "C1", "Kehadiran")
	// loop for  untuk nampilin perulangan data di sql
	INPUTGURU := 2
	for kolom_guru.Next() {
		var mapel, guru, hadir string
		kolom_guru.Scan(&mapel, &guru, &hadir)
		guru_sekolah.SetCellValue(sheet, fmt.Sprintf("A%d", INPUTGURU), mapel)
		guru_sekolah.SetCellValue(sheet, fmt.Sprintf("B%d", INPUTGURU), guru)
		guru_sekolah.SetCellValue(sheet, fmt.Sprintf("C%d", INPUTGURU), hadir)
		INPUTGURU++
	}

	guru.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	guru.Header().Set("Content-Disposition", `attachment; filename="data_guru.xlsx"`)
	guru_sekolah.Write(guru)
}
