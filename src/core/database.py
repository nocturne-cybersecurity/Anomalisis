
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, Union
from config import settings
from config.security import is_port_safe, is_critical_port, validate_port, validate_ip

class Database:
        def __init__(self, db_path: Optional[Path] = None):
            self.db_path = db_path or settings.DB_PATH
            self._init_db()

        def _get_connection(self):
            return sqlite3.connect(str(self.db_path))

        def _init_db(self):
            with self._get_connection() as conn:
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
                    );
                    
                    CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip);
                    CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
                    
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        action TEXT NOT NULL,
                        details TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                    )
                """)
                conn.commit()

        def save_scan(self, ip: str, output: str, scan_args: str = None) -> bool:
            """
            Guarda el resultado de un escaneo en la base de datos.
            
            Args:
                ip: Dirección IP escaneada
                output: Salida cruda de Nmap
                scan_args: Argumentos usados en el escaneo
                
            Returns:
                bool: True si se guardó correctamente, False en caso contrario
            """
            try:
                opened_ports = self._parse_ports_from_output(output, 'open')
                closed_ports = self._parse_ports_from_output(output, 'closed')
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO scans 
                        (ip, output, ports_opened, ports_closed, scan_arguments)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            ip, 
                            output,
                            json.dumps(opened_ports),
                            json.dumps(closed_ports),
                            scan_args or ''
                        )
                    )
                    scan_id = cursor.lastrowid
                    
                    # Registrar en el historial
                    self._log_scan_action(
                        scan_id,
                        'scan_completed',
                        f'Escaneo completado para {ip} con {len(opened_ports)} puertos abiertos'
                    )
                    
                    return True
            except Exception as e:
                print(f"[!] Error al guardar el escaneo: {e}")
                return False
                
        def _parse_ports_from_output(self, output: str, state: str) -> List[int]:
            """Extrae los puertos con un estado específico de la salida de Nmap."""
            import re
            pattern = fr'(\d+)/tcp\s+{state}'
            return [int(port) for port in re.findall(pattern, output)]
            
        def _log_scan_action(self, scan_id: int, action: str, details: str = '') -> None:
            """Registra una acción en el historial de escaneos."""
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO scan_history (scan_id, action, details)
                        VALUES (?, ?, ?)
                        """,
                        (scan_id, action, details)
                    )
            except Exception as e:
                print(f"[!] Error al registrar acción en el historial: {e}")

        def get_last_scan(self, ip: str) -> Optional[Dict[str, Any]]:
            """
            Obtiene el último escaneo para una IP específica.
            
            Args:
                ip: Dirección IP a buscar
                
            Returns:
                Dict con los datos del escaneo o None si no se encuentra
            """
            try:
                with self._get_connection() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        SELECT * FROM scans 
                        WHERE ip = ? 
                        ORDER BY timestamp DESC 
                        LIMIT 1
                        """,
                        (ip,)
                    )
                    row = cursor.fetchone()
                    if not row:
                        return None
                        
                    # Convertir a diccionario y procesar los puertos
                    scan_data = dict(row)
                    scan_data['ports_opened'] = json.loads(scan_data.get('ports_opened', '[]'))
                    scan_data['ports_closed'] = json.loads(scan_data.get('ports_closed', '[]'))
                    
                    # Obtener historial de acciones
                    cursor.execute(
                        """
                        SELECT action, details, timestamp 
                        FROM scan_history 
                        WHERE scan_id = ? 
                        ORDER BY timestamp DESC
                        """,
                        (scan_data['id'],)
                    )
                    scan_data['history'] = [dict(row) for row in cursor.fetchall()]
                    
                    return scan_data
            except Exception as e:
                print(f"[!] Error al obtener el último escaneo: {e}")
                return None

        def get_all_scans(self, ip: str = None) -> List[Dict[str, Any]]:
            """
            Obtiene todos los escaneos, opcionalmente filtrados por IP.
            
            Args:
                ip: (Opcional) Filtrar por dirección IP
                
            Returns:
                Lista de diccionarios con los datos de los escaneos
            """
            try:
                with self._get_connection() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    if ip:
                        cursor.execute(
                            """
                            SELECT id, ip, timestamp, 
                                   json_array_length(ports_opened, '$') as open_ports_count
                            FROM scans 
                            WHERE ip = ? 
                            ORDER BY timestamp DESC
                            """,
                            (ip,)
                        )
                    else:
                        cursor.execute("""
                            SELECT id, ip, timestamp, 
                                   json_array_length(ports_opened, '$') as open_ports_count
                            FROM scans 
                            ORDER BY timestamp DESC
                            """)
                    
                    return [dict(row) for row in cursor.fetchall()]
            except Exception as e:
                print(f"[!] Error al obtener los escaneos: {e}")
                return []
                
        def search_scans(self, 
                       ip: str = None, 
                       port: int = None, 
                       protocol: str = 'tcp',
                       limit: int = 100) -> List[Dict[str, Any]]:
            """
            Busca escaneos que coincidan con los criterios especificados.
            
            Args:
                ip: (Opcional) Dirección IP o rango de red
                port: (Opcional) Número de puerto
                protocol: Protocolo a buscar (tcp/udp), por defecto 'tcp'
                limit: Límite de resultados a devolver
                
            Returns:
                Lista de escaneos que coinciden con los criterios
            """
            try:
                query = """
                    SELECT DISTINCT s.* 
                    FROM scans s
                    WHERE 1=1
                """
                params = []
                
                if ip:
                    query += " AND s.ip LIKE ?"
                    params.append(f"%{ip}%")
                    
                if port is not None:
                    # Buscar en puertos abiertos o cerrados
                    query += " AND (json_extract(s.ports_opened, '$') LIKE ? OR json_extract(s.ports_closed, '$') LIKE ?)"
                    port_str = f'%"{port}"%'
                    params.extend([port_str, port_str])
                
                query += " ORDER BY s.timestamp DESC LIMIT ?"
                params.append(limit)
                
                with self._get_connection() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute(query, params)
                    
                    results = []
                    for row in cursor.fetchall():
                        scan_data = dict(row)
                        scan_data['ports_opened'] = json.loads(scan_data.get('ports_opened', '[]'))
                        scan_data['ports_closed'] = json.loads(scan_data.get('ports_closed', '[]'))
                        results.append(scan_data)
                        
                    return results
                    
            except Exception as e:
                print(f"[!] Error al buscar escaneos: {e}")
                return []
                
        def get_scan_history(self, scan_id: int) -> List[Dict[str, Any]]:
            """
            Obtiene el historial de acciones para un escaneo específico.
            
            Args:
                scan_id: ID del escaneo
                
            Returns:
                Lista de acciones realizadas en el escaneo
            """
            try:
                with self._get_connection() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        SELECT action, details, timestamp 
                        FROM scan_history 
                        WHERE scan_id = ? 
                        ORDER BY timestamp DESC
                        """,
                        (scan_id,)
                    )
                    return [dict(row) for row in cursor.fetchall()]
            except Exception as e:
                print(f"[!] Error al obtener el historial del escaneo: {e}")
                return []