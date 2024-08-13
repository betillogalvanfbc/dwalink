package main

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
)

type Activity struct {
	Name     string `xml:"name,attr"`
	Exported string `xml:"exported,attr"`
}

type Manifest struct {
	PackageName string     `xml:"package,attr"`
	Activities  []Activity `xml:"application>activity"`
}

func main() {
	apkPath := flag.String("apk", "", "Ruta al archivo .apk a analizar")
	wordlistPath := flag.String("w", "", "Ruta al archivo de wordlist a utilizar")
	url := flag.String("u", "", "Especificar una URL única para fuzzing")
	listActivities := flag.Bool("list", false, "Listar todas las actividades y salir")
	flag.Parse()

	if *apkPath == "" || (*wordlistPath == "" && *url == "" && !*listActivities) {
		fmt.Println("Debes proporcionar la ruta al archivo .apk y una wordlist o una URL.")
		flag.Usage()
		os.Exit(1)
	}

	if err := processAPK(*apkPath, *wordlistPath, *url, *listActivities); err != nil {
		fmt.Printf("Error durante el procesamiento del APK: %v\n", err)
	} else if !*listActivities {
		fmt.Println("Fuzzing completado exitosamente.")
	}
}

func processAPK(apkPath, wordlistPath, url string, listActivities bool) error {
	outputDir := "apk_output"
	defer os.RemoveAll(outputDir) // Limpieza automática al final

	if err := decompileApk(apkPath, outputDir); err != nil {
		return fmt.Errorf("error durante la descompilación: %v", err)
	}

	manifest, err := parseManifest(filepath.Join(outputDir, "AndroidManifest.xml"))
	if err != nil {
		return fmt.Errorf("error analizando el AndroidManifest.xml: %v", err)
	}

	// Imprimir la información del paquete
	fmt.Printf("Información del paquete:\n")
	fmt.Printf("Nombre del paquete: %s\n", manifest.PackageName)

	activities := getAllActivities(manifest)

	// Imprimir la cantidad de actividades encontradas
	fmt.Printf("Total de actividades encontradas: %d\n", len(activities))

	if listActivities {
		printAllActivities(activities)
		return nil
	}

	if len(activities) == 0 {
		return fmt.Errorf("no se encontraron actividades")
	}

	var words []string
	if wordlistPath != "" {
		words, err = readWordlist(wordlistPath)
		if err != nil {
			return fmt.Errorf("error leyendo la wordlist: %v", err)
		}
	}

	if url != "" {
		return fuzzWithURL(manifest.PackageName, activities, url)
	}

	return fuzzActivities(manifest.PackageName, activities, words)
}

func decompileApk(apkPath, outputDir string) error {
	cmd := exec.Command("apktool", "d", apkPath, "-o", outputDir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func parseManifest(manifestPath string) (*Manifest, error) {
	data, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer AndroidManifest.xml: %v", err)
	}
	var manifest Manifest
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("error al analizar AndroidManifest.xml: %v", err)
	}
	return &manifest, nil
}

func getAllActivities(manifest *Manifest) []Activity {
	return manifest.Activities
}

func printAllActivities(activities []Activity) {
	fmt.Println("Lista de todas las actividades encontradas:")
	for _, activity := range activities {
		exported := "no exportada"
		if activity.Exported == "true" {
			exported = "exportada"
		}
		fmt.Printf("Actividad: %s, Estado: %s\n", activity.Name, exported)
	}
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

	return words, scanner.Err()
}

func fuzzActivities(packageName string, activities []Activity, words []string) error {
	for _, activity := range activities {
		for _, word := range words {
			url := fmt.Sprintf("https://example.com/%s", word)
			command := fmt.Sprintf("adb shell am start -n %s/%s -d '%s'", packageName, activity.Name, url)
			fmt.Println(command)
			if err := runADBCommand(command); err != nil {
				fmt.Printf("Error ejecutando comando adb para %s: %v\n", activity.Name, err)
			}
			fmt.Println("Presiona Enter para continuar...")
			fmt.Scanln() // Esperar a que el usuario presione Enter
		}
	}
	return nil
}

func fuzzWithURL(packageName string, activities []Activity, url string) error {
	for _, activity := range activities {
		command := fmt.Sprintf("adb shell am start -n %s/%s -d '%s'", packageName, activity.Name, url)
		fmt.Println(command)
		if err := runADBCommand(command); err != nil {
			fmt.Printf("Error ejecutando comando adb para %s: %v\n", activity.Name, err)
		}
		fmt.Println("Presiona Enter para continuar...")
		fmt.Scanln() // Esperar a que el usuario presione Enter
	}
	return nil
}

func runADBCommand(command string) error {
	cmd := exec.Command("bash", "-c", command)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error ejecutando comando adb: %v, %s", err, stderr.String())
	}
	return nil
}
