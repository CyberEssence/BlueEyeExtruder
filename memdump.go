package main

import (
 "fmt"
 "os"
)

const (
 memDevice = "/proc/kcore" // Устройство для доступа к оперативной памяти
 bufferSize = 4096      // Размер буфера для чтения
)

func main() {
 if len(os.Args) < 2 {
  fmt.Println("Usage: sudo ./ram_dump <output_file.bin>")
  os.Exit(1)
 }
 outputFile := os.Args[1]

 file, err := os.Create(outputFile)
 if err != nil {
  fmt.Printf("Failed to create output file: %v\n", err)
  os.Exit(1)
 }
 defer file.Close()

 // Открываем устройство /proc/kcore
 mem, err := os.Open(memDevice)
 if err != nil {
  fmt.Printf("Failed to open %s: %v\n", memDevice, err)
  os.Exit(1)
 }
 defer mem.Close()

 buffer := make([]byte, bufferSize)

 fmt.Println("Dumping RAM...")
 for {
  // Чтение данных из /proc/kcore
  n, err := mem.Read(buffer)
  if err != nil {
   fmt.Printf("Failed to read from %s: %v\n", memDevice, err)
   break
  }

  _, err = file.Write(buffer[:n])
  if err != nil {
   fmt.Printf("Failed to write to output file: %v\n", err)
   break
  }
 }

 fmt.Println("RAM dump completed.")
}