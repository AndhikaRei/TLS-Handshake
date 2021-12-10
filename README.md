# TLS Handshake

*Program Studi Teknik Informatika* <br />
*Sekolah Teknik Elektro dan Informatika* <br />
*Institut Teknologi Bandung* <br />

*Semester I Tahun 2021/2022*

## Description
Implementasi TLS Handshake sederhana mengikuti protokol yang sudah diajarkan di kelas. TCP Handshake juga diimplementasikan di program ini. Setelah proses handshake selesai, program ini akan melakukan simulasi pengiriman berkas sederhana dan closing connection. Ada beberapa asumsi yang digunakan untuk menurunkan kompleksitas dari program yang dibuat:
1. Program akan terdiri dari client dan server yang dijalankan di satu komputer
2. Data akan dikirimkan dalam bentuk segment, lengkapnya bisa refer ke makalah
3. Tidak ada packet loss, dupplication, corrupt, reorder, dan sebagainya
4. Operasi terkait digital signature dilakukan menggunakan fungsi dan data dummy
5. TLS handshake diimplementasikan dengan algoritma RSA, saat key session sudah di generate maka komunikasi akan diencrypt dan decrypt dengan algoritma AES (Bagian komunikasi di encrypt/decrypt tidak diimplementasikan di program)

## Author
1. Reihan Andhika Putra (13519043)

## Requirements
- [Python 3](https://www.python.org/downloads/)
  
## Installation
Clone the repository
```bash
git clone https://gitlab.informatika.org/hokkysss/if3130_tubes02_team_galactic.git
cd src
```
## How To Run
Server:
```bash
python server.py [port] [path berkas]
```
Cient:
```bash
python client.py [port client] [port server] [path penyimpanan berkas]
```