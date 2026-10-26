import concurrent.futures
import subprocess

PORTS = ["COM8", "COM10", "COM11", "COM13", "COM14"]
BAUD = "921600"

BINARIES = [
    ("0x0", "build/bootloader/bootloader.bin"),
    ("0x8000", "build/partition_table/partition-table.bin"),
    (
        "0x10000",
        "build/node.bin",
    ),  # <-- Pamiętaj o zmianie na nazwę swojego pliku .bin!
]


def flash_port(port):
  # Używamy oficjalnego launchera Windows "py -3", żeby ominąć zmienne środowiskowe VS Code
  cmd = [
      "py",
      "-3",
      "-m",
      "esptool",
      "--chip",
      "esp32c3",
      "--port",
      port,
      "--baud",
      BAUD,
      "--before",
      "default_reset",
      "--after",
      "hard_reset",
      "write_flash",
      "-z",
      "--flash_mode",
      "dio",
      "--flash_freq",
      "80m",
      "--flash_size",
      "detect",
  ]

  for addr, path in BINARIES:
    cmd.extend([addr, path])

  print(f"[{port}] Rozpoczęto wgrywanie na ESP32-C3...")
  result = subprocess.run(cmd, capture_output=True, text=True)

  if result.returncode == 0:
    print(f"[{port}] Sukces! Wgrano pomyślnie.")
  else:
    print(f"[{port}] Błąd wgrywania:\n{result.stderr}")


def main():
  with concurrent.futures.ThreadPoolExecutor() as executor:
    list(executor.map(flash_port, PORTS))


if __name__ == "__main__":
  main()