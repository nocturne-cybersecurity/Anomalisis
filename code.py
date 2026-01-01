# !/usr/bin/env python3
#Hecho por Nocturne

import os
import re
import json
import socket
import sqlite3
import argparse
import subprocess
from pathlib import Path
from colorama import Fore, Back, Style
from typing import Optional, List, Dict, Any

try:
    def list_database_entries(db_path: str = "database/scan_results.db") -> None:
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scans)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'timestamp' in columns:
                cursor.execute("""
                    SELECT id, ip, 
                           CASE 
                               WHEN timestamp IS NULL OR timestamp = '' THEN 'N/A'
                               ELSE strftime('%Y-%m-%d %H:%M:%S', timestamp) 
                           END as formatted_date 
                    FROM scans 
                    ORDER BY timestamp DESC
                """)
            else:
                cursor.execute("SELECT id, ip, 'N/A' as formatted_date FROM scans")

            scans = cursor.fetchall()

            if not scans:
                print("No scan entries found in the database.")
                return

            print("\nScan hisotry")
            for scan in scans:
                print(f"ID: {scan['id']} | IP: {scan['ip']} | Date: {scan['formatted_date']}")
            print("=======================================================\n")

        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            if 'conn' in locals() and conn:
                conn.close()
    def show_scan_details(scan_id: int, db_path: str = "database/scan_results.db") -> None:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ip, output, timestamp 
                FROM scans 
                WHERE id = ?
            """, (scan_id,))
            result = cursor.fetchone()
            if not result:
                print(f"No scan found with ID: {scan_id}")
                return
            ip, output, timestamp = result
            print(f"\n=== Scan Details ===")
            print(f"Scan ID: {scan_id}")
            print(f"IP: {ip}")
            print(f"Date: {timestamp}")
            print("\nScan Results:")
            print(output)
            print("===================\n")
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            if conn:
                conn.close()

    def parse_arguments():
        parser = argparse.ArgumentParser(
            description="Anomalisis - Network Security Scanner",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        scan_group = parser.add_argument_group('Scan Options')
        scan_group.add_argument(
            'target',
            nargs='?',
            help='Target IP or hostname to scan'
        )
        scan_group.add_argument(
            '-p', '--ports',
            default='1-1024',
            help='Ports to scan (e.g., 80,443 or 1-1000)'
        )
        scan_group.add_argument(
            '-o', '--output',
            choices=['text', 'json'],
            default='text',
            help='Output format (default: text)'
        )
        scan_group.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

        db_group = parser.add_argument_group('Database Options')
        db_group.add_argument(
            '-d', '--database',
            action='store_true',
            help='List all scan history'
        )
        db_group.add_argument(
            '--show-scan',
            type=int,
            metavar='SCAN_ID',
            help='Show details of a specific scan by ID'
        )
        db_group.add_argument(
            '--db-path',
            default='database/scan_results.db',
            help='Path to the SQLite database file'
        )

        compare_group = parser.add_argument_group('Comparison Options')
        compare_group.add_argument(
            '--compare',
            nargs=2,
            metavar=('SCAN_ID_1', 'SCAN_ID_2'),
            help='Compare two scans by their IDs'
        )

        parser.add_argument(
            '--version',
            action='version',
            version='Anomalisis 1.0'
        )

        return parser.parse_args()


    def main():
        args = parse_arguments()

        try:
            if args.database:
                list_database_entries(args.db_path)
                return

            if args.show_scan:
                show_scan_details(args.show_scan, args.db_path)
                return

            if args.compare:
                scan1_id, scan2_id = args.compare
                print(f"Comparing scans {scan1_id} and {scan2_id}")
                return

            if not args.target:
                print("Error: No target specified. Use -h for help.")
                return 1

            os.system("clear")
            print(f"Starting scan of {args.target}...")
            init_scan()

        except KeyboardInterrupt:
            print("\nScan cancelled by user.")
            return 1
        except Exception as e:
            print(f"An error occurred: {e}", file=sys.stderr)
            return 1

        return 0

    def get_local_ip():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except Exception as e:
            print(f"[!] Error al obtener la IP local: {e}")
            return "127.0.0.1"
    def run_nmap(target_ip):
        result = subprocess.run(
            ["nmap", "-sV", target_ip],
            capture_output=True,
            text=True
        )
        return result.stdout
    def init_db():
        try:
            os.makedirs("database", exist_ok=True)
            db_path = os.path.abspath("database/scan_results.db")
            print(f"[+] Inicializando base de datos en: {db_path}")

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    output TEXT NOT NULL,
                    ports_opened TEXT NOT NULL,
                    ports_closed TEXT NOT NULL,
                    scan_arguments TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
            """)

            conn.commit()
            conn.close()
            print("[+] Base de datos inicializada correctamente")
            return True

        except Exception as e:
            print(f"[!] Error al inicializar la base de datos: {e}")
            if 'conn' in locals() and conn:
                conn.rollback()
                conn.close()
            return False

    def get_last_scan(ip):

        conn = None
        try:
            db_dir = 'database'
            db_path = os.path.abspath(os.path.join(db_dir, 'scan_results.db'))
            os.makedirs(db_dir, exist_ok=True)

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='scans'
            """)

            if not cursor.fetchone():
                return None

            cursor.execute("""
                SELECT output FROM scans 
                WHERE ip = ? 
                ORDER BY timestamp DESC, id DESC 
                LIMIT 1
            """, (ip,))

            result = cursor.fetchone()
            return result['output'] if result else None

        except sqlite3.Error as e:
            print(f"[!] Error de base de datos al obtener el último escaneo: {e}")
            return None
        except Exception as e:
            print(f"[!] Error inesperado al obtener el último escaneo: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass

    def save_scan(ip, output, scan_args=None):

        print("\n[DEBUG] Iniciando save_scan")
        print(f"[DEBUG] IP: {ip}")
        print(f"[DEBUG] Output length: {len(output)} caracteres")

        conn = None
        try:

            db_dir = 'database'
            db_path = os.path.abspath(os.path.join(db_dir, 'scan_results.db'))
            os.makedirs(db_dir, exist_ok=True)
            print(f"[DEBUG] Ruta de la base de datos: {db_path}")

            if not os.access(db_dir, os.W_OK):
                print(f"[ERROR] No se puede escribir en el directorio: {os.path.abspath(db_dir)}")
                return False

            print("[DEBUG] Conectando a la base de datos...")
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            def parse_ports(output_text, state):
                import re
                pattern = fr'(\d+)/tcp\s+{state}'
                return [int(port) for port in re.findall(pattern, output_text)]

            open_ports = parse_ports(output, 'open')
            closed_ports = parse_ports(output, 'closed')

            print("[DEBUG] Insertando nuevo registro...")
            cursor.execute(
                """
                INSERT INTO scans 
                (ip, output, ports_opened, ports_closed, scan_arguments)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    ip,
                    output,
                    json.dumps(open_ports),
                    json.dumps(closed_ports),
                    scan_args or ''
                )
            )

            scan_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO scan_history 
                (scan_id, action, details) 
                VALUES (?, ?, ?)
                """,
                (scan_id, 'scan_completed', f'Escaneo completado para {ip} con {len(open_ports)} puertos abiertos')
            )
            cursor.execute("SELECT COUNT(*) FROM scans WHERE ip = ?", (ip,))
            count = cursor.fetchone()[0]
            print(f"[DEBUG] Total de escaneos para {ip}: {count}")

            conn.commit()
            print(f"[+] Escaneo guardado correctamente para IP: {ip} (ID: {scan_id})")
            return True

        except sqlite3.Error as e:
            print(f"[!] Error de base de datos al guardar el escaneo: {e}")
            if 'conn' in locals() and conn:
                conn.rollback()
            return False

        except Exception as e:
            import traceback
            print(f"[!] Error inesperado al guardar el escaneo: {e}")
            print(f"[DEBUG] Traceback: {traceback.format_exc()}")
            if 'conn' in locals() and conn:
                conn.rollback()
            return False

        finally:
            if conn:
                try:
                    conn.close()
                except Exception as e:
                    print(f"[DEBUG] Error al cerrar la conexión: {e}")
    def cerrar_puertos(puertos):
        try:
            subprocess.run(["which", "ufw"], check=True, capture_output=True)

            ufw_status = subprocess.run(
                ["sudo", "ufw", "status"],
                capture_output=True,
                text=True
            )

            if "inactive" in ufw_status.stdout.lower():
                print("[!] ufw está inactivo. Activando...")
                subprocess.run(["sudo", "ufw", "enable"], check=True)

            for puerto_info in puertos:
                puerto = puerto_info.split('/')[0]
                try:
                    subprocess.run(
                        ["sudo", "ufw", "deny", f"{puerto}/tcp"],
                        check=True
                    )
                    print(f"[+] Regla añadida para cerrar el puerto {puerto}/tcp")
                except subprocess.CalledProcessError as e:
                    print(f"[!] Error al cerrar el puerto {puerto}: {e}")

            print("\n[+] Para ver las reglas actuales, ejecuta: sudo ufw status")
            print("[!] Los cambios son permanentes. Para revertir: sudo ufw delete deny [puerto]/tcp")

        except subprocess.CalledProcessError:
            print("[!] ufw no está instalado. Por favor instálalo con: sudo apt install ufw")

    def run_nmap(target_ip):
        result = subprocess.run(
            ["nmap", "-sV", target_ip],
            capture_output=True,
            text=True
        )
        output_lines = result.stdout.split('\n')
        open_ports = []
        port_section = False
        for line in output_lines:
            if 'PORT' in line and 'STATE' in line and 'SERVICE' in line:
                port_section = True
                continue
            if port_section:
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0].strip()
                    service = line.split()[-2] if len(line.split()) >= 4 else 'unknown'
                    port_info = f"{port}/tcp - {service}"
                    open_ports.append(port_info)
                    print(f"[+] Puerto abierto: {port_info}")
                elif line.strip() == '':
                    port_section = False
        if not open_ports:
            print("[!] No se encontraron puertos abiertos")
            return []
        if open_ports:
            print("\n" + "="*50)
            cerrar = input("\n¿Desea cerrar los puertos abiertos? (s/n): ").strip().lower()
            if cerrar == 's':
                print("\n[!] Se requieren permisos de administrador para cerrar puertos")
                print("[!] Se cerrarán los siguientes puertos:")
                for puerto in open_ports:
                    print(f"    - {puerto}")
                confirmar = input("\n¿Está seguro? (s/n): ").strip().lower()
                if confirmar == 's':
                    cerrar_puertos(open_ports)

        return open_ports
    def ports():
        ports_file = "json/ports.json"
        try:
            with open(ports_file, 'r') as f:
                datos = json.load(f)
                ports = datos.get('ports', [])
                print(f"[+] Cargando {len(ports)} puertos disponibles")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Error al leer el archivo: {e}")
            print("[-] Usando puertos por defecto.")
            ports = [80, 443, 22, 21, 25]
        return ports
    def get_last_scan(ip):
        try:
            conn = sqlite3.connect("database/scan_results.db")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT output FROM scans WHERE ip = ? ORDER BY id DESC LIMIT 1",
                (ip,)
            )
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else None
        except Exception as e:
            print(f"[!] Error al obtener el último escaneo: {e}")
            return None


    def compare_scans(old_scan, new_scan):
        if not old_scan:
            return "No hay escaneo anterior para comparar"

        old_ports = set(re.findall(r'(\d+)/tcp\s+\w+\s+', old_scan))
        new_ports = set(re.findall(r'(\d+)/tcp\s+\w+\s+', new_scan))

        added = new_ports - old_ports
        removed = old_ports - new_ports

        report = []
        if added:
            report.append(f"Puertos nuevos: {', '.join(sorted(added))}")
        if removed:
            report.append(f"Puertos cerrados: {', '.join(sorted(removed))}")

        return "\n".join(report) if report else "No hay cambios en los puertos abiertos"


    def init():
        local_ip = get_local_ip()
        print(f"[+] IP local: {local_ip}")
        init_db()
        print(f"[+] Escaneando {local_ip}...\n")
        open_ports = run_nmap(local_ip)

        if open_ports:
            save_scan(local_ip, "\n".join(open_ports))
            print("[+] Resultados guardados en SQLite")

    def banner():
        print(f'''{Fore.LIGHTRED_EX}
                                                             
           (                               (                 
           )\                   )       )  )\ (      (       
        ((((_)(   (      (     (     ( /( ((_))\  (  )\  (   
         )\ _ )\  )\ )   )\    )\  ' )(_)) _ ((_) )\((_) )\  
         (_)_\(_)_(_/(  ((_) _((_)) ((_)_ | | (_)((_)(_)((_) 
          / _ \ | ' \))/ _ \| '  \()/ _` || | | |(_-<| |(_-< 
         /_/ \_\|_||_| \___/|_|_|_| \__,_||_| |_|/__/|_|/__/
         Anomalisis - Nocturne
    ''')

        #Si quieres crear banners como estos ve a: https://manytools.org/hacker-tools/ascii-banner/
        #la verdad a mí me encanta esa página y agradezco que exista

    def eject():
        banner()
        print("\nPara detener usa ctrl + C")
        init()

except SyntaxWarning:
    pass


    if __name__ == "__main__":
        sys.exit(main())
