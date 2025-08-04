package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

// 為了轉 json 時，遵從名稱小寫慣例的作法
type FileMeta struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
}

var (
	storageDir = "./storage"
	mapFile    = "file_map.json"
	fileMap    = make(map[string]FileMeta)
	mapLock    = sync.RWMutex{}
	key        = []byte("1234567890abcdef1234567890ghijkl") //32 bytes AES key
)

func main() {
	os.MkdirAll(storageDir, 0755)
	loadMap()

	r := mux.NewRouter()
	r.HandleFunc("/file/upload", uploadHandler).Methods("POST")
	r.HandleFunc("/file/download/{code}", downloadHandler).Methods("GET")

	// http.ListenAndServe(":8080", r)
	// log.Println("Server started at :8080")
	// if err := http.ListenAndServe(":8080", r); err != nil {
	// 	log.Fatal(err)
	// }

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Println("Server started at :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	<-quit // 等待中斷訊號
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // 5秒後若無法正常完成就強制結束
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Println("Server exited properly")
}

func loadMap() {
	data, err := os.ReadFile(mapFile)
	if err == nil {
		json.Unmarshal(data, &fileMap)
	}
}

func saveMap() {
	// data, err := json.Marshal(fileMap)	// 擠在一行
	data, err := json.MarshalIndent(fileMap, "", "  ") // 格式化排版
	if err != nil {
		println("marshal failed:", err.Error())
		return
	}
	err = os.WriteFile(mapFile, data, 0644)
	if err != nil {
		println("write file failed:", err.Error())
	}
}

func encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// 將 nonce 與加密資料一併回傳
	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file not found", http.StatusBadRequest)
		return
	}
	defer file.Close()

	originalName := header.Filename

	// 讀檔案內容並計算 SHA1
	data, _ := io.ReadAll(file)
	hash := sha1.Sum(data)
	sha1Code := hex.EncodeToString(hash[:])

	// 加密並存檔
	encData, err := encrypt(data)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}
	filePath := filepath.Join(storageDir, sha1Code+".enc")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// 檔案不存在才寫入
		err = os.WriteFile(filePath, encData, 0644)
		if err != nil {
			http.Error(w, "write failed", http.StatusInternalServerError)
			return
		}
	}

	// 更新 map 並存檔
	{
		mapLock.Lock()
		defer mapLock.Unlock()

		if _, exists := fileMap[sha1Code]; !exists {
			fileMap[sha1Code] = FileMeta{
				Path:     filePath,
				Filename: originalName,
			}
			saveMap()
		}
	} // 這個區塊結束時 defer 會執行，鎖會提前釋放

	w.Write([]byte(sha1Code))
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	code := mux.Vars(r)["code"]
	mapLock.RLock()
	meta, ok := fileMap[code]
	mapLock.RUnlock()

	if !ok {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	encData, err := os.ReadFile(meta.Path)
	if err != nil {
		http.Error(w, "cannot read file", http.StatusInternalServerError)
		return
	}
	data, err := decrypt(encData)
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+meta.Filename+"\"")
	w.Write(data)
}
