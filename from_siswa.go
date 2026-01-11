package models

type Nama_siswa struct {
	ID            int
	SiswaID       int
	AdminID       *int
	Nama          string
	Kelas         string
	Jenis_Kelamin string
	Hari_Jadwal   string
	Kehadiran     string
}
