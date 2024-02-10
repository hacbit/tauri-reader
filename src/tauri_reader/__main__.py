from . import TauriReader
import sys

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m tauri_reader <path to tauri app>")
        sys.exit(1)

    tauri_app_path = sys.argv[1]
    tauri_reader = TauriReader(tauri_app_path)
    tauri_reader.extract()

if __name__ == '__main__':
    main()