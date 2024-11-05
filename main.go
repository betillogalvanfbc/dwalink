package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const asciiArt = `
 ██████╗ ██╗    ██╗ █████╗ ██╗     ██╗███╗   ██╗██╗  ██╗
██╔═══██╗██║    ██║██╔══██╗██║     ██║████╗  ██║██║ ██╔╝
██║   ██║██║ █╗ ██║███████║██║     ██║██╔██╗ ██║█████╔╝ 
██║   ██║██║███╗██║██╔══██║██║     ██║██║╚██╗██║██╔═██╗ 
╚██████╔╝╚███╔███╔╝██║  ██║███████╗██║██║ ╚████║██║  ██╗
 ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
`

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

type IntentFilter struct {
	Data []Data `xml:"data"`
}

type Data struct {
	Scheme     string `xml:"scheme,attr"`
	Host       string `xml:"host,attr"`
	AutoVerify string `xml:"autoVerify,attr"`
}

type Manifest struct {
	IntentFilters []IntentFilter `xml:"application>activity>intent-filter"`
}

func decompileApk(apkPath, outputDir string) error {
	fmt.Printf("Descompilando %s...\n", apkPath)
	cmd := exec.Command("apktool", "d", apkPath, "-o", outputDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func parseManifest(manifestPath string) (*Manifest, error) {
	xmlFile, err := os.Open(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir AndroidManifest.xml: %v", err)
	}
	defer xmlFile.Close()

	byteValue, _ := ioutil.ReadAll(xmlFile)
	var manifest Manifest
	err = xml.Unmarshal(byteValue, &manifest)
	if err != nil {
		return nil, fmt.Errorf("error al analizar AndroidManifest.xml: %v", err)
	}

	return &manifest, nil
}

func findLinks(manifest *Manifest) (deepLinks, webLinks, appLinks []string) {
	for _, filter := range manifest.IntentFilters {
		for _, data := range filter.Data {
			if data.Scheme != "" && data.Scheme != "http" && data.Scheme != "https" {
				deepLinks = append(deepLinks, fmt.Sprintf("%s://%s", data.Scheme, data.Host))
			} else if data.Scheme == "http" || data.Scheme == "https" {
				if data.AutoVerify == "true" {
					appLinks = append(appLinks, fmt.Sprintf("%s://%s", data.Scheme, data.Host))
				} else {
					webLinks = append(webLinks, fmt.Sprintf("%s://%s", data.Scheme, data.Host))
				}
			}
		}
	}
	return
}

func cleanUp(directory string) {
	err := os.RemoveAll(directory)
	if err != nil {
		fmt.Printf("Error al eliminar archivos temporales: %v\n", err)
	} else {
		fmt.Printf("Archivos temporales eliminados de %s\n", directory)
	}
}

func generateFuzzString() string {
	cmd := exec.Command("radamsa")
	cmd.Stdin = bytes.NewBufferString("💩")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error ejecutando radamsa: %v\n", err)
		return ""
	}
	return strings.TrimSpace(out.String())
}

func runADBCommandWithTimeout(command string, timeout time.Duration) error {
	// Crear un contexto con timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Ejecutar el comando
	err := cmd.Run()

	// Verificar si el contexto ha expirado
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("timeout alcanzado para el comando adb")
	}

	if err != nil {
		return fmt.Errorf("comando adb fallido: %s, %v", stderr.String(), err)
	}

	return nil
}

func readWordlist(wordlistPath string) ([]string, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir la wordlist: %v", err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		words = append(words, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error leyendo la wordlist: %v", err)
	}

	return words, nil
}

func deeplinkFuzzFunction(directory, wordlistPath string) {
	manifestPath := filepath.Join(directory, "AndroidManifest.xml")
	manifest, err := parseManifest(manifestPath)
	if err != nil {
		fmt.Printf("Error analizando el AndroidManifest.xml: %v\n", err)
		return
	}

	deeplinks, _, _ := findLinks(manifest)

	words, err := readWordlist(wordlistPath)
	if err != nil {
		fmt.Printf("Error leyendo la wordlist: %v\n", err)
		return
	}

	for _, word := range words {
		for _, deeplink := range deeplinks {
			url := fmt.Sprintf("%s/%s", deeplink, word)
			command := fmt.Sprintf(`adb shell am start -W -a android.intent.action.VIEW -d '%s'`, url)
			fmt.Println(command)
			err := runADBCommandWithTimeout(command, 2*time.Second) // 5 segundos de timeout
			if err != nil {
				fmt.Printf("Error ejecutando comando adb para %s: %v\n", url, err)
				continue // Pasar a la siguiente palabra si hay un error
			}
		}
	}
}

func analyzeApk(apkPath, wordlistPath string) {
	outputDir := "apk_output"

	err := decompileApk(apkPath, outputDir)
	if err != nil {
		fmt.Printf("Error durante la descompilación: %v\n", err)
		return
	}

	manifestPath := filepath.Join(outputDir, "AndroidManifest.xml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		fmt.Println("No se encontró AndroidManifest.xml. Verifica la descompilación.")
		cleanUp(outputDir)
		return
	}

	manifest, err := parseManifest(manifestPath)
	if err != nil {
		fmt.Println(err)
		cleanUp(outputDir)
		return
	}

	deeplinks, weblinks, applinks := findLinks(manifest)
	fmt.Printf("%sDeeplinks encontrados: %s%s%s\n", colorBlue, colorGreen, deeplinks, colorReset)
	fmt.Printf("%sWeblinks encontrados: %s%s%s\n", colorBlue, colorGreen, weblinks, colorReset)
	fmt.Printf("%sApplinks encontrados: %s%s%s\n", colorBlue, colorGreen, applinks, colorReset)

	// Ejecución de fuzzing de deeplinks
	deeplinkFuzzFunction(outputDir, wordlistPath)

	cleanUp(outputDir)
}

func printCommonFunctions() {
	fmt.Println("Funciones Comunes para Manejar Weblinks, Deeplinks, y Applinks:")
	fmt.Println("1. getPath() - Devuelve la parte de la ruta del URI.")
	fmt.Println("   Ejemplo: String path = uri.getPath();")
	fmt.Println("2. getScheme() - Devuelve el esquema del URI (por ejemplo, http, https, myapp).")
	fmt.Println("   Ejemplo: String scheme = uri.getScheme();")
	fmt.Println("3. getHost() - Devuelve el host del URI.")
	fmt.Println("   Ejemplo: String host = uri.getHost();")
	fmt.Println("4. getQueryParameter(String key) - Devuelve el valor de un parámetro de consulta específico.")
	fmt.Println("   Ejemplo: String value = uri.getQueryParameter(\"id\");")
	fmt.Println("5. getFragment() - Devuelve el fragmento del URI (la parte después del #).")
	fmt.Println("   Ejemplo: String fragment = uri.getFragment();")
	fmt.Println("6. getAuthority() - Devuelve la autoridad del URI, que generalmente incluye el host y la información del puerto.")
	fmt.Println("   Ejemplo: String authority = uri.getAuthority();")
	fmt.Println("7. getLastPathSegment() - Devuelve el último segmento del path del URI.")
	fmt.Println("   Ejemplo: String lastSegment = uri.getLastPathSegment();")
	fmt.Println("8. getPathSegments() - Devuelve una lista de los segmentos del path.")
	fmt.Println("   Ejemplo: List<String> segments = uri.getPathSegments();")
	fmt.Println("9. startsWith(String prefix) - Verifica si una cadena comienza con un prefijo específico.")
	fmt.Println("   Ejemplo: boolean startsWithWeb = uri.getPath().startsWith(\"/web\");")
	fmt.Println("10. Intent.getData() - Devuelve el URI que inició el intento.")
	fmt.Println("    Ejemplo: Uri uri = intent.getData();")
}

func main() {
	fmt.Println(asciiArt)
	showHelp := flag.Bool("h", false, "Mostrar funciones comunes para manejar weblinks, deeplinks, y applinks")
	apkPath := flag.String("apk", "", "Ruta al archivo .apk a analizar")
	wordlistPath := flag.String("w", "", "Ruta al archivo de wordlist a utilizar")
	flag.Parse()

	if *showHelp {
		printCommonFunctions()
		os.Exit(0)
	}

	if *apkPath == "" {
		fmt.Println("Debes proporcionar la ruta al archivo .apk.")
		flag.Usage()
		os.Exit(1)
	}

	if *wordlistPath == "" {
		fmt.Println("Debes proporcionar la ruta al archivo de wordlist.")
		flag.Usage()
		os.Exit(1)
	}

	analyzeApk(*apkPath, *wordlistPath)
}
