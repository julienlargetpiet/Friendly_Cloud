package main

import (
  "fmt"
  "os"
  "time"
  "io"
  "net/http"
  "html/template"
  "database/sql"
  "crypto/aes"
  _"github.com/go-sql-driver/mysql"
)

const port_run string = "8080"
const secret_key string = "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47"
var db *sql.DB
var templates = template.Must(template.ParseFiles("templates/search.html",
                                          "templates/upload.html"))

var ref_nb = [10]uint8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}

var ref_ltr = [52]uint8{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}

var ref_spechr = [24]uint8{'!', '.', ':', ';', '\\', '-', '%', '*', ',', '_', '/', '<', '>', '=', '[', ']', '\'', '{', '}', '[', ']', '(', ')', '"'}

var ref_temp_password = [11]uint8{'-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}

var unix_allowed_filename_char = [63]uint8{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '.'}

var banned_char_username = [22]uint8{'_', ' ', '/', '?', '$', 
                           '&', '@', '#', '.', ',', '\\', '|', 
                           '{', '}', '(', ')', '^', '<', '>', '%', ':'}

var only_usernames = []string{"Arkose", "Julien", "Lucas"}

var only_usrs = false

type DataFile struct {
  Title string
  Body []byte
}

type SearchStruct struct {
  Files []string
  FilesName []string
  NextURL string
}

type UploadStruct struct {
  NextURL string
}

var banned_usernames = [6]string{"Root", "ROOT", "root", "Admin", "ADMIN", "admin"}

func ConnectDatabase() (*sql.DB, error) {
  var credentials = "kvv:1234@(localhost:3306)/friendly_cloud"
  db, err := sql.Open("mysql", credentials)
  if err != nil {
    return nil, err
  }
  return db, nil
}

func LoadFile(title *string) (*DataFile, error) {
  body, err := os.ReadFile(*title)
  if err != nil {
    return nil, err
  }
  return &DataFile{Title: *title, Body: body}, nil
}

func render_template_search(w http.ResponseWriter, title *string, p *SearchStruct) {
  err := templates.ExecuteTemplate(w, *title, p)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
  }
}

func render_template_upload_page(w http.ResponseWriter, 
                                title *string, 
                                p *UploadStruct) {
  err := templates.ExecuteTemplate(w, *title, p)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
  }
}

func render_template_no_data(w http.ResponseWriter, p *DataFile) {
  w.Write(p.Body)
}

func Int64ToString(x *int64) string {
  const base int64 = 10
  var remainder int64
  rtn_str := ""
  for *x > 0 {
    remainder = *x % base
    rtn_str = string(remainder + 48) + rtn_str
    *x -= remainder
    *x /= 10
  }
  return rtn_str
}

func Int32ToString(x *int32) string {
  const base int32 = 10
  var remainder int32
  rtn_str := ""
  for *x > 0 {
    remainder = *x % base
    rtn_str = string(remainder + 48) + rtn_str
    *x -= remainder
    *x /= 10
  }
  return rtn_str
}

func StringToInt32(x string) int32 {
  var ref_nb = [10]uint8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
  var rtn_val int32 = 0
  var lngth int = len(x)
  var i2 int32
  var cur_rn uint8
  var i int
  for i = 0; i + 1 < lngth; i++ {
    cur_rn = x[i]
    i2 = 0
    for cur_rn != ref_nb[i2]{
      i2++
    }
    rtn_val += i2
    rtn_val *= 10
  }
  cur_rn = x[i]
  i2 = 0
  for cur_rn != ref_nb[i2]{
    i2++
  }
  rtn_val += i2
  return rtn_val
}

func ValidateFilename(filename string) bool {
  var in_it bool
  var i2 int
  var cur_chr uint8
  for i := 0; i < len(filename); i++ {
    in_it = false
    cur_chr = filename[i]
    for i2 = 0; i2 < 63; i2++ {
      if cur_chr == unix_allowed_filename_char[i2] {
        in_it = true
        break
      }
    }
    if !in_it {
      return false
    }
  }
  return true
}

func GoodUsername(given_username string) bool {
  if len(given_username) == 0 {
    return false
  }
  for i:= 0; i < len(given_username); i++ {
    if given_username[i] == ' ' {
      return false
    }
  }
  for _, usr := range banned_usernames {
    if given_username == usr {
      return false
    }
  }
  var is_in = false
  if only_usrs {
    for _, usr := range banned_usernames {
      if given_username == usr {
        is_in = true
        break
      }
    }
    if !is_in {
      return false
    }
  }
  return true 
}

func GoodPassword(given_password string) bool {
  var n int = len(given_password)
  if n != 16 {
    return false
  }
  var i uint = 0
  var i2 uint
  var cur_val uint8
  var agn bool = true
  for agn && i < 16 {
    cur_val = given_password[i]
    i2 = 0
    for i2 < 10 && cur_val != ref_nb[i2] {
      i2++
    }
    if i2 < 10 {
      agn = false
    }
    i++
  }
  if agn {
    return false
  }
  agn = true
  i = 0
  for agn && i < 16 {
    cur_val = given_password[i]
    i2 = 0
    for i2 < 52 && cur_val != ref_ltr[i2] {
      i2++
    }
    if i2 < 52 {
      agn = false
    }
    i++
  }
  i = 0
  if agn {
    return false
  }
  agn = true
  for agn && i < 16 {
    cur_val = given_password[i]
    i2 = 0
    for i2 < 24 && cur_val != ref_spechr[i2] {
      i2++
    }
    if i2 < 24 {
      agn = false
    }
    i++
  }
  if agn {
    return false
  }
  return true
}

func EvaluateConnectionPassword(given_password *string, username *string, db *sql.DB) bool {
  var real_password string
  username_query := db.QueryRow("SELECT password FROM credentials WHERE username = ?;", username)
  err := username_query.Scan(&real_password)
  if err != nil {
    fmt.Println(err)
    return false
  }
  if real_password != *given_password {
    return false
  }
  return true
}

func EvaluatePassword(given_password *string, username *string, db *sql.DB) bool {
  var real_password string
  username_query := db.QueryRow("SELECT temp_password FROM credentials WHERE username = ?;", username)
  err := username_query.Scan(&real_password)
  if err != nil {
    return false
  }
  if real_password != *given_password {
    return false
  }
  return true
}

func URLToCredentials(url string) (string, string, bool) {
  rtn_str := ""
  rtn_str2 := ""
  var i int = len(url) - 1
  var i3 int
  n_ref := i
  var cur_bool bool
  for url[i] != '_' {
    cur_bool = false
    for i3 = 0; i3 < 11; i3++ {
      if url[i] == ref_temp_password[i3] {
        cur_bool = true
        break
      }
    }
    if !cur_bool {
      return "", "", false
    }
    rtn_str += string(url[i])
    i--
  }
  if i == n_ref {
    return "", "", false
  }
  i--
  for url[i] != '_' {
    for i3 = 0; i3 < 3; i3++ {
      if url[i] == banned_char_username[i3] {
        return "", "", false
      }
    }
    rtn_str2 += string(url[i])
    i--
  }
  i = 0
  var n int = len(rtn_str)
  password_rune := []rune(rtn_str)
  var tmp_val rune
  for i < n / 2 {
    tmp_val = password_rune[i]
    password_rune[i] = password_rune[n - 1 - i]
    password_rune[n - 1 - i] = tmp_val
    i++
  }
  username_rune := []rune(rtn_str2)
  n = len(rtn_str2)
  i = 0
  for i < n / 2 {
    tmp_val = username_rune[i]
    username_rune[i] = username_rune[n - 1 - i]
    username_rune[n - 1 - i] = tmp_val
    i++
  }
  return string(password_rune), string(username_rune), true
}

func CredentialsToURL(tmp_password string, username *string, db *sql.DB) (string, error) {
  cur_time := time.Now().Unix()
  string_time := Int64ToString(&cur_time)
  string_time = string_time[len(string_time) - 4:]
  tmp_password = tmp_password[:12]
  tmp_password += string_time
  
  aes, err := aes.NewCipher([]byte(secret_key))
  if err != nil {
    return "", err
  }
  
  ciphered_password := make([]byte, 16)
  aes.Encrypt(ciphered_password, []byte(tmp_password))
  
  p_rotated_link := ""
  var cur_str string
  var cur_rune int32
  var rotated_link string
  
  for i := 0; i < 16; i++ {
    cur_rune = int32(ciphered_password[i])
    cur_str = Int32ToString(&cur_rune) + "-"
    p_rotated_link += cur_str
  }
  
  _, err = db.Exec("UPDATE credentials SET temp_password=? WHERE username=?;", p_rotated_link, *username)
  rotated_link = "_" + *username + "_" + p_rotated_link

  return rotated_link, nil
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("<b>Forbidden Method</b>"))
    return
  }
  if r.URL.Path != "/" {
    w.Write([]byte("<b>404 Not Found</b>"))
    return
  }
  cur_title := "templates/index.html"
  cur_page, err := LoadFile(&cur_title)
  if err != nil {
    fmt.Println(err)
    return
  }
  render_template_no_data(w, cur_page)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("<b>Forbidden Method</b>"))
    return
  }
  if r.URL.Path != "/login/" {
    w.Write([]byte("<b>404 Not Found</b>"))
    return
  }
  cur_title := "templates/login.html"
  cur_page, err := LoadFile(&cur_title)
  if err != nil {
    fmt.Println(err)
    return
  }
  render_template_no_data(w, cur_page)
}

func NotValidConnectionHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("<b>Bad Method</b>"))
    return
  } else {
    w.Write([]byte(`<b>Username or Password incorrect</b><br>
      <a href="http://0.0.0.0:` + port_run + `/login/">Go Back</a>`))
  }
}

func ConnectionHandler(db *sql.DB) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
      w.Write([]byte("<b>Forbidden Method</b>"))
      return
    }

    username_form := r.FormValue("username")
    password_form := r.FormValue("password")
    
    rtn_bool := EvaluateConnectionPassword(&password_form, 
                                           &username_form, 
                                           db)

    if !rtn_bool {
      http.Redirect(w, r, "/not_valid_connection/", http.StatusFound)
      return
    } else {
      rotated_link, err := CredentialsToURL(password_form, 
                                        &username_form, 
                                        db) 
      if err != nil {
        fmt.Println(err)
        return
      }
      http.Redirect(w, r, "/search/" + rotated_link, http.StatusFound)
    }
  }
}

func CreateAccountHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("<b>Forbidden Method</b>"))
    return
  }
  if r.URL.Path != "/create_account/" {
    w.Write([]byte("<b>404 Not Found</b>"))
    return
  }
  cur_title := "templates/create_account.html"
  cur_page, err := LoadFile(&cur_title)
  if err != nil {
    fmt.Println(err)
    return
  }
  render_template_no_data(w, cur_page)
}

func AlreadyNewAccountHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("Wrong Method"))
    return
  }
  if r.URL.Path != "/already_new_account/" {
    w.Write([]byte("<b>404, Page Not Found</b>"))
    return
  }
  w.Write([]byte(`<b>Username already used</b><br>
  <a href="http://0.0.0.0:` + port_run + `/create_account/">Go back</a>`))
}

func BadPasswordNewAccountHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("Wrong Method"))
    return
  }
  if r.URL.Path != "/bad_password_new_account/" {
    w.Write([]byte("<b>404, Page Not Found</b>"))
    return
  }
  w.Write([]byte(`<b>Password Must be 16 characters long with at least numbers and letters and allowed special characters</b> <br> <a href="http://0.0.0.0:` + port_run + `/create_account/">Go back</a>`))
}

func BadUsernameNewAccountHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("Wrong Method"))
    return
  }
  if r.URL.Path != "/bad_username_new_account/" {
    w.Write([]byte("<b>404, Page Not Found</b>"))
    return
  }
  w.Write([]byte(`<b>bad username, maybe banned or empty</b> <br> <a href="http://0.0.0.0:` + port_run + `/create_account/">Go back</a>`))
}

func NewAccountHandler(db *sql.DB) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
      w.Write([]byte("<b>Forbidden Method</b>"))
      return
    }
    form_username := r.FormValue("username")
    good_cnt := GoodUsername(form_username)
    if !good_cnt {
      http.Redirect(w, r, "/bad_username_new_account/", http.StatusFound)
      return
    }
    var new_username string
    
    content_query := db.QueryRow("SELECT username FROM credentials WHERE username=?;", form_username)
    err := content_query.Scan(&new_username)
    if err == nil {
      fmt.Println(err)
      http.Redirect(w, r, "/already_new_account/", http.StatusFound)
      return
    } else {
      form_password := r.FormValue("password")
      good_cnt = GoodPassword(form_password)
      if !good_cnt {
        http.Redirect(w, r, "/bad_password_new_account/", 
                      http.StatusFound)
        return
      } else {

        os.Mkdir(form_username, 0777) 
        fmt.Println("good")
        fmt.Println(form_username)

        _, err = db.Exec("CREATE TABLE " + form_username + " (filename VARCHAR(255));")       
        if err != nil {
          fmt.Println(err)
          w.Write([]byte("<b>Something went wrong</b>"))
          return
        }

        _, err = db.Exec("INSERT INTO credentials VALUE (?, ?, ' ');", 
                          form_username, form_password)
        if err != nil {
          fmt.Println(err)
          w.Write([]byte("<b>Something went wrong</b>"))
          return
        }
         
        http.Redirect(w, r, "/login/", http.StatusFound)
        return
      }
    }
  }
}

func SearchHandler(db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
      w.Write([]byte("<b>Bad Method</b>"))
      return
    }
    password, username, valid_url := URLToCredentials(r.URL.Path)
    if !valid_url {
      w.Write([]byte("<b>Bad URL format</b>"))
      return
    }
    var is_valid bool = EvaluatePassword(&password, &username, db)
    search_ptrn := ""
    if !is_valid {
      w.Write([]byte("<b>Not allowed to be here</b>"))
      return
    } else { 
      i := 8
      my_url := r.URL.Path
      n := len(my_url)
      for i < n && my_url[i] != '_' {
        search_ptrn += string(my_url[i])
        i++ 
      }
      if search_ptrn == "" {
        search_ptrn = "."
      }

      rotated_link, err := CredentialsToURL(password, &username, db)
      if err != nil {
        fmt.Println(err)
        return
      }
      password, _, _ = URLToCredentials(rotated_link)

      var cur_filename string
      var my_filesname []string
      query_string := "SELECT filename FROM " + username + " WHERE filename RLIKE '" + search_ptrn + "';"
      content_query2, err := db.Query(query_string)
      if err != nil {
        fmt.Println(err)
        return
      }
      for content_query2.Next() {
        err = content_query2.Scan(&cur_filename)
        if err != nil {
          fmt.Println(err)
          return
        }
        my_filesname = append(my_filesname, cur_filename)
      }
 
      cur_struct := &SearchStruct{FilesName: my_filesname,
                                  NextURL: rotated_link}
      cur_title := "search.html"

      render_template_search(w, &cur_title, cur_struct)
    }
  }
}

func SearchPatternHandler(db *sql.DB) http.HandlerFunc {
 return func (w http.ResponseWriter, r *http.Request) {
   if r.Method != "POST" {
     w.Write([]byte("<b>Bad Method</b>"))
     return
   }
   my_url := r.URL.Path
   password, username, is_valid := URLToCredentials(my_url)
   if !is_valid {
     w.Write([]byte("<b>Bad URL format</b>"))
     return
   } else {
     is_valid = EvaluatePassword(&password, &username, db)
     if !is_valid {
       w.Write([]byte("<b>Not allowed to be here</b>"))
       return
     } else {
       rotated_link, err := CredentialsToURL(password, &username, db)
       if err != nil {
         fmt.Println(err)
         return
       }
       pattern := r.FormValue("myPattern")
       rotated_link = pattern + rotated_link
       http.Redirect(w, r, "/search/" + rotated_link, http.StatusFound)
     }
   }
 }
}

func UploadPageHandler(db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
      w.Write([]byte("<b>Bad Method</b>"))
      return
    }
    my_url := r.URL.Path
    password, username, is_valid := URLToCredentials(my_url)
    if !is_valid {
      w.Write([]byte("<b>Bad URL Format</b>"))
      return
    }
    is_valid = EvaluatePassword(&password, &username, db)
    if !is_valid {
      w.Write([]byte("<b>Not allowed to be here</b>"))
      return
    } else {
      page_title := "upload.html"
      rotated_link, err := CredentialsToURL(password, &username, db)
      if err != nil {
        fmt.Println(err)
        return
      }
      cur_page := &UploadStruct{NextURL: rotated_link}
      render_template_upload_page(w, &page_title, cur_page)
    }
  }
}

func UploadHandler(db *sql.DB) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
      w.Write([]byte("<b>Bad Method</b>"))
      return
    }
    var found_alrd_file string
    my_url := r.URL.Path
    password, username, is_valid := URLToCredentials(my_url)
    if !is_valid {
      w.Write([]byte("<b>URL is not valid</b>"))
      return
    }
    is_valid = EvaluatePassword(&password, &username, db)
    if !is_valid {
      w.Write([]byte("<b>Not allowed to be here</b>"))
      return
    }
    r.ParseMultipartForm(10 << 20)
    file, handler, err := r.FormFile("myFile")
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something wrong with the Fileform request</b>"))
      return
    } else {
      filename := handler.Filename
      is_valid := ValidateFilename(filename)
      if !is_valid {
        w.Write([]byte("<b>Bad Unix filename</b>"))
        fmt.Println(err)
        return
      } else {
        content_query := db.QueryRow("SELECT filename FROM " + username + " WHERE filename=?;", filename)
        err = content_query.Scan(&found_alrd_file)
        if err == nil {
          w.Write([]byte(`<b>Filename already taken</b><br><a href="../upload_page/_` + username + "_" + password + `">Go Back</a>`))
          return
        }
        fileBytes, err := io.ReadAll(file)
        if err != nil {
          fmt.Println(err)
          return
        }
        err = os.WriteFile(username + "/" + filename, fileBytes, 0644)
        _, err = db.Exec("INSERT INTO " + username + " VALUE (?);", filename)
        if err != nil {
          fmt.Println(err)
          w.Write([]byte("<b>Something went wrong</b>"))
          return
        }
        rotated_link, err := CredentialsToURL(password, &username, db) 
        if err != nil {
          fmt.Println(err)
          return
        }
        http.Redirect(w, r, "/search/" + rotated_link, http.StatusFound)
      }
    }
  }
}

func NotExistingDownloadPageHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("<b>Bad Method</b>"))
    return
  } else if r.URL.Path != "/not_existing_download_page" {
    w.Write([]byte("<b>Bad URL format</b>"))
  } else {
    w.Write([]byte("<b>The file does not exist</b>"))
  }
}

func DownloadHandler(db *sql.DB) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
      w.Write([]byte("<b>Forbidden Method</b>"))
      return
    }
    my_url := r.URL.Path
    password, username, is_valid := URLToCredentials(my_url)
    if !is_valid {
      w.Write([]byte("<b>Not allowed to be here and/or bad url format</b>"))
      return
    } else {
      is_valid = EvaluatePassword(&password, &username, db)
      if !is_valid {
        w.Write([]byte("<b>Not allowed to be here</b>"))
        return
      }
      i := 10
      my_file := ""
      for my_url[i] != '_' {
        my_file += string(my_url[i])
        i++
      }
      bytes_data, err := os.ReadFile(username + "/" + my_file)
      if err != nil {
        http.Redirect(w, r, "/not_existing_download_page/", 
                      http.StatusFound)
        return 
      } else {
        w.Write(bytes_data)
      }
    }
  }
}

func DeleteFileHandler(db *sql.DB) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
      w.Write([]byte("<b>Bad Method</b>"))
      return
    }
    my_url := r.URL.Path
    var found_filename string
    password, username, is_valid := URLToCredentials(my_url)
    if !is_valid {
      w.Write([]byte("<b>Bad URL format</b>"))
      return
    } else {
      is_valid = EvaluatePassword(&password, &username, db)
      if !is_valid {
        w.Write([]byte("Not allowed to be here"))
        return
      } else {
        filename := ""
        i := 8
        for my_url[i] != '_' {
          filename += string(my_url[i])
          i++
        }
        content_query := db.QueryRow("SELECT filename FROM " + username + " WHERE filename=?;", filename)
        err := content_query.Scan(&found_filename)
        if err != nil {
          w.Write([]byte(`<b>This file does not exist</b><br><a href="../search/_` + username + `_` + password + `">Go Back</a>`))
          return
        } else {
          _, err = db.Exec("DELETE FROM " + username + " WHERE filename=?;", filename)
          if err != nil {
            w.Write([]byte("Something went wrong"))
            return
          } else {
            http.Redirect(w, r, "/search/_" + username + "_" + password, http.StatusFound)
            return
          }
        }
      }
    }
  }
}

func main() {
  
  db, err := ConnectDatabase()
  if err != nil {
    fmt.Println(err)
    return
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/", 
             IndexHandler)
  
  mux.HandleFunc("/login/", 
                 LoginHandler)
  mux.HandleFunc("/not_valid_connection/", 
                  NotValidConnectionHandler)
  mux.HandleFunc("/connection/", 
                  ConnectionHandler(db))

  mux.HandleFunc("/create_account/", 
                  CreateAccountHandler)
  mux.HandleFunc("/already_new_account/", 
                  AlreadyNewAccountHandler)
  mux.HandleFunc("/bad_username_new_account/", 
                  BadUsernameNewAccountHandler)
  mux.HandleFunc("/bad_password_new_account/", 
                  BadPasswordNewAccountHandler)
  mux.HandleFunc("/new_account/", 
                  NewAccountHandler(db))
     
  mux.HandleFunc("/search/", 
                 SearchHandler(db))
  mux.HandleFunc("/search_pattern/", 
                 SearchPatternHandler(db))

     
  mux.HandleFunc("/upload_page/", 
                  UploadPageHandler(db))
  mux.HandleFunc("/upload/", 
                 UploadHandler(db))

  mux.HandleFunc("/download/", 
                 DownloadHandler(db))
  mux.HandleFunc("/not_existing_download_page/", 
                  NotExistingDownloadPageHandler)

  mux.HandleFunc("/delete/", 
             DeleteFileHandler(db))

  mux.Handle("/static/", 
            http.FileServer(http.Dir(".")))

  
  // NOT IN PRODUCTION
  err = http.ListenAndServe("0.0.0.0:" + port_run, mux)
  if err != nil {
    fmt.Println("Failed to start server...")
    fmt.Print(err)
    return
  }

  // IN PRODUCTION
  //err := http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
  //if err != nil {
  //    log.Fatalf("ListenAndServeTLS failed: %v", err)
  //}

}


