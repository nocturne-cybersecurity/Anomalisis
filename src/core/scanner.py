
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime

class PortScanner:
    def __init__(self, db_path: Optional[Path] = None):
        self.db = Database(db_path)
        self.local_ip = self._get_local_ip()
        self.last_scan = None

    def _get_local_ip(self) -> str:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
            
    def _validate_scan_target(self, target: str) -> Tuple[bool, str]:
        if not target:
            return False, "No se especificó un objetivo para el escaneo"
            
        if not validate_ip(target) and target != 'localhost':
            return False, f"Dirección IP o rango inválido: {target}"
            
        return True, ""
        
    def _validate_ports(self, ports: List[int]) -> Tuple[bool, str]:
        if not ports:
            return True, ""

        invalid_ports = [p for p in ports if not validate_port(p)]
        if invalid_ports:
            return False, f"Puertos inválidos: {', '.join(map(str, invalid_ports))}"
            
        return True, ""
        
    def _check_critical_ports(self, ports: List[int]) -> Tuple[bool, List[int]]:
        critical_found = [p for p in ports if is_critical_port(p)]
        return len(critical_found) > 0, critical_found
        
    def _confirm_critical_ports(self, ports: List[int]) -> bool:
        critical_ports = ", ".join(str(p) for p in ports)
        print(f"\n[!] ADVERTENCIA: Estás a punto de escanear puertos críticos: {critical_ports}")
        print("   Estos puertos son esenciales para la seguridad del sistema.")
        
        try:
            response = input("   ¿Deseas continuar? (s/n): ").strip().lower()
            return response == 's' or response == 'si'
        except (KeyboardInterrupt, EOFError):
            return False
            
    def _get_safe_ports_args(self, ports: List[int] = None) -> str:
        if not ports:
            safe_ports = ",".join(map(str, sorted(SAFE_PORTS)))
        else:
            safe_ports = ",".join(str(p) for p in ports if is_port_safe(p))
            
        return f"-p {safe_ports}" if safe_ports else ""
        
    def run_nmap_scan(self, 
                     target: str = None, 
                     ports: List[int] = None,
                     safe_mode: bool = True,
                     args: str = None) -> Dict[str, Any]:
        target = target or self.local_ip
        args = args or settings.NMAP_ARGS
        
        is_valid, error_msg = self._validate_scan_target(target)
        if not is_valid:
            return {"error": error_msg, "success": False}
            
        if ports:
            is_valid, error_msg = self._validate_ports(ports)
            if not is_valid:
                return {"error": error_msg, "success": False}
            has_critical, critical_ports = self._check_critical_ports(ports)
            if has_critical and not self._confirm_critical_ports(critical_ports):
                return {
                    "error": "Escaneo cancelado por el usuario",
                    "success": False
                }

        nmap_cmd = ["nmap"]
        if ports:
            ports_arg = ",".join(map(str, ports))
            nmap_cmd.extend(["-p", ports_arg])
        elif safe_mode:

            safe_ports = ",".join(map(str, sorted(SAFE_PORTS)))
            nmap_cmd.extend(["-p", safe_ports])
            
        if args:
            nmap_cmd.extend(args.split())
            
        nmap_cmd.append(target)
        
        try:
            print(f"[+] Iniciando escaneo de {target}...")
            if ports:
                print(f"    Puertos: {', '.join(map(str, ports))}")
            elif safe_mode:
                print(f"    Modo seguro: solo puertos de la lista blanca")
                
            start_time = time.time()
            
            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            if result.returncode != 0:
                return {
                    "error": f"Error en el escaneo: {result.stderr}",
                    "success": False
                }
                
            scan_output = result.stdout
            open_ports = self._parse_ports_from_output(scan_output, 'open')
            closed_ports = self._parse_ports_from_output(scan_output, 'closed')
            critical_open = [p for p in open_ports if is_critical_port(p)]
            scan_args = " ".join(nmap_cmd[1:])  # Excluir 'nmap' del comando
            self.db.save_scan(target, scan_output, scan_args)
            result = {
                "success": True,
                "target": target,
                "command": " ".join(nmap_cmd),
                "output": scan_output,
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "critical_ports_open": critical_open,
                "duration_seconds": round(duration, 2),
                "timestamp": datetime.now().isoformat()
            }
            self.last_scan = result
            return result
        except Exception as e:
            error_msg = f"Error al ejecutar Nmap: {str(e)}"
            print(f"[!] {error_msg}")
            return {"error": error_msg, "success": False}

    @staticmethod
    def _parse_ports_from_output(output: str, state: str) -> List[int]:
        pattern = fr'(\d+)/tcp\s+{state}'
        return [int(port) for port in re.findall(pattern, output)]

    def compare_scans(self, old_scan: Dict, new_scan: Dict) -> Dict[str, List[int]]:
        old_ports = set(old_scan.get('open_ports', [])) if old_scan else set()
        new_ports = set(new_scan.get('open_ports', []))
        
        return {
            "added": sorted(new_ports - old_ports),
            "removed": sorted(old_ports - new_ports),
            "unchanged": sorted(new_ports & old_ports)
        }
    
    def scan_and_compare(self, 
                        target: str = None, 
                        ports: List[int] = None,
                        safe_mode: bool = True) -> Dict:

        target = target or self.local_ip
        last_scan = self.db.get_last_scan(target)
        new_scan = self.run_nmap_scan(target, ports, safe_mode)
        
        if not new_scan.get('success', False):
            return {
                "error": new_scan.get('error', 'Error desconocido en el escaneo'),
                "success": False
            }
        changes = {}
        if last_scan:
            changes = self.compare_scans(last_scan, new_scan)
            
            # Verificar si hay puertos críticos recién abiertos
            new_critical = [p for p in changes.get('added', []) if is_critical_port(p)]
            if new_critical:
                print(f"\n[!] ADVERTENCIA: Se detectaron puertos críticos abiertos recientemente: {', '.join(map(str, new_critical))}")
        
        # Preparar resultado
        result = {
            "success": True,
            "target": target,
            "scan_id": new_scan.get('scan_id'),
            "timestamp": new_scan['timestamp'],
            "duration_seconds": new_scan['duration_seconds'],
            "open_ports": new_scan['open_ports'],
            "closed_ports": new_scan['closed_ports'],
            "changes": changes,
            "critical_ports_open": new_scan['critical_ports_open']
        }
        
        return result
        
    def get_port_status(self, target: str, port: int) -> Dict[str, Any]:
        if not validate_port(port):
            return {"error": f"Número de puerto inválido: {port}", "success": False}
        is_safe = is_port_safe(port)
        is_critical = is_critical_port(port)

        result = self.run_nmap_scan(
            target=target,
            ports=[port],
            args="-T4 --open"
        )
        
        if not result.get('success', False):
            return result
            
        is_open = port in result.get('open_ports', [])
        
        return {
            "success": True,
            "target": target,
            "port": port,
            "is_open": is_open,
            "is_safe": is_safe,
            "is_critical": is_critical,
            "last_checked": datetime.now().isoformat()
        }
        
    def search_scans(self, 
                    ip: str = None, 
                    port: int = None, 
                    protocol: str = 'tcp',
                    limit: int = 100) -> List[Dict[str, Any]]:
        return self.db.search_scans(ip=ip, port=port, protocol=protocol, limit=limit)
        
    def get_scan_history(self, scan_id: int = None) -> List[Dict[str, Any]]:
        if scan_id is None:
            if not self.last_scan or 'scan_id' not in self.last_scan:
                return []
            scan_id = self.last_scan['scan_id']
            
        return self.db.get_scan_history(scan_id)
