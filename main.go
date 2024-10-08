package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Структура для обработки префиксов
type Prefix struct {
	Prefix string `json:"Prefix"`
	Count  int    `json:"Count"`
	Total  int    `json:"Total"`
}

// Структура для общего ответа API
type ApiResponse struct {
	Prefixes []Prefix `json:"prefixes"`
}

// Структура для сохранения префиксов в файл
type PrefixForFile struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// Функция для чтения доменов из файла
func readDomainsFromFile(filename string) ([]string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Разбиваем данные файла на строки (домен на каждой строке)
	domains := strings.Split(strings.TrimSpace(string(data)), "\n")
	return domains, nil
}

// Выполнение команды dig для получения IP-адресов домена
func getIPsByDig(domain string) ([]string, error) {
	cmd := exec.Command("dig", "+short", domain)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run dig command: %w", err)
	}

	ips := strings.Split(strings.TrimSpace(out.String()), "\n")
	return ips, nil
}

// Получение номера AS по IP-адресу через whois
func getASNumberByWhois(ip string) (int, error) {
	cmd := exec.Command("whois", ip)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("failed to run whois command: %w", err)
	}

	// Регулярное выражение для поиска AS номера
	re := regexp.MustCompile(`OriginAS:\s+AS(\d+)`)
	match := re.FindStringSubmatch(out.String())
	if len(match) < 2 {
		return 0, fmt.Errorf("AS number not found in whois response")
	}

	asNumber := match[1]
	return strconv.Atoi(asNumber)
}

// Функция для получения IP префиксов по AS номеру
func getIPPrefixes(asNumber int) ([]Prefix, error) {
	url := fmt.Sprintf("https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/%d", asNumber)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 response: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var apiResponse ApiResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return apiResponse.Prefixes, nil
}

// Функция для сохранения префиксов в файл
func savePrefixesToFile(data []PrefixForFile, filename string) error {
	// Сериализуем данные в JSON
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Записываем JSON в файл
	if err := ioutil.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON to file: %w", err)
	}

	return nil
}
func main() {
	// Получение пути к исполняемому файлу
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error getting executable path:", err)
		return
	}

	exeDir := filepath.Dir(exePath)
	domainsFilePath := filepath.Join(exeDir, "domains.txt")

	// Чтение списка доменов из файла
	domains, err := readDomainsFromFile(domainsFilePath)
	if err != nil {
		fmt.Println("Error reading domains:", err)
		return
	}

	// Создаем массив для хранения результатов
	var results []PrefixForFile

	// Проходим по каждому домену
	for _, domain := range domains {
		fmt.Printf("Processing domain: %s\n", domain)

		ips, err := getIPsByDig(domain)
		if err != nil {
			fmt.Printf("Error getting IPs for domain %s: %v\n", domain, err)
			continue
		}

		if len(ips) == 0 {
			fmt.Printf("No IPs found for domain: %s\n", domain)
			continue
		}

		asNumber, err := getASNumberByWhois(ips[0])
		if err != nil {
			fmt.Printf("Error getting AS number for domain %s: %v\n", domain, err)
			continue
		}

		fmt.Printf("AS Number for domain %s (IP: %s): %d\n", domain, ips[0], asNumber)

		prefixes, err := getIPPrefixes(asNumber)
		if err != nil {
			fmt.Printf("Error getting IP prefixes for AS %d (domain: %s): %v\n", asNumber, domain, err)
			continue
		}

		for _, prefix := range prefixes {
			results = append(results, PrefixForFile{
				Hostname: prefix.Prefix,
				IP:       "", // Оставляем пустым
			})
		}
	}

	// Сохраняем результаты в ту же директорию, что и бинарный файл
	outputFilePath := filepath.Join(exeDir, "prefix.json")
	if err := savePrefixesToFile(results, outputFilePath); err != nil {
		fmt.Println("Error saving prefixes:", err)
		return
	}

	fmt.Printf("Prefixes saved to %s\n", outputFilePath)
}
