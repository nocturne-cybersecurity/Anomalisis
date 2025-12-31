#!/usr/bin/env python3
"""
Interfaz de línea de comandos para el escáner de puertos mejorado.
"""
import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

from core.scanner import PortScanner
from core.database import Database
from config.security import SAFE_PORTS, CRITICAL_PORTS

# Configuración de la consola
console = Console()


def print_banner():
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

def print_help():
    """Muestra la ayuda de comandos disponibles."""
    help_text = """
[bold]Comandos disponibles:[/bold]

[bold]Escaneo:[/bold]
  scan [IP] [--ports PORTS]  Escanear una IP o rango
  rescan                     Repetir el último escaneo
  portcheck IP PORT          Verificar estado de un puerto específico

[bold]Historial:[/bold]
  history [IP]               Mostrar historial de escaneos
  show SCAN_ID               Mostrar detalles de un escaneo
  search [--ip IP] [--port PORT]  Buscar en los resultados

[bold]Seguridad:[/bold]
  safe-ports                 Mostrar lista de puertos seguros
  critical-ports             Mostrar puertos críticos

[bold]Otros:[/bold]
  help                      Mostrar esta ayuda
  exit                      Salir del programa
    """
    console.print(Panel(help_text, title="[bold]Ayuda[/bold]", border_style="blue"))

def print_safe_ports():
    """Muestra la lista de puertos seguros."""
    table = Table(title="[bold]Puertos Seguros[/bold]", box=box.ROUNDED)
    table.add_column("Puerto", justify="center")
    table.add_column("Servicio")
    
    port_services = {
        20: "FTP (Data)",
        21: "FTP (Control)",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        123: "NTP",
        143: "IMAP",
        389: "LDAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP (Submission)",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP Proxy",
        8443: "HTTPS Alternativo"
    }
    
    for port in sorted(SAFE_PORTS):
        service = port_services.get(port, "Desconocido")
        table.add_row(f"[green]{port}[/green]", service)
    
    console.print(table)

def print_critical_ports():
    """Muestra la lista de puertos críticos."""
    table = Table(title="[bold]Puertos Críticos[/bold]", box=box.ROUNDED)
    table.add_column("Puerto", justify="center")
    table.add_column("Servicio")
    table.add_column("Riesgo")
    
    critical_info = {
        22: ("SSH", "Alto - Acceso remoto"),
        23: ("Telnet", "Crítico - Sin cifrado"),
        80: ("HTTP", "Medio - Sin cifrado"),
        443: ("HTTPS", "Medio - Tráfico web seguro"),
        3389: ("RDP", "Alto - Escritorio remoto"),
        3306: ("MySQL", "Alto - Base de datos"),
        5432: ("PostgreSQL", "Alto - Base de datos"),
        27017: ("MongoDB", "Alto - Base de datos")
    }
    
    for port in sorted(CRITICAL_PORTS):
        if port in critical_info:
            service, risk = critical_info[port]
            table.add_row(
                f"[red]{port}[/red]", 
                service, 
                f"[yellow]{risk}[/yellow]"
            )
    
    console.print(table)

def print_scan_results(scan_data: Dict[str, Any]):
    """Muestra los resultados de un escaneo en formato de tabla."""
    if not scan_data.get('success', False):
        console.print(f"[red]Error:[/red] {scan_data.get('error', 'Error desconocido')}")
        return
    
    # Panel de resumen
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="cyan", justify="right")
    summary.add_column(style="white")
    
    summary.add_row("Objetivo:", f"[bold]{scan_data['target']}")
    summary.add_row("Fecha:", scan_data.get('timestamp', 'N/A'))
    summary.add_row("Duración:", f"{scan_data.get('duration_seconds', 0):.2f} segundos")
    
    # Mostrar puertos abiertos
    open_ports = scan_data.get('open_ports', [])
    critical_ports = [p for p in open_ports if p in CRITICAL_PORTS]
    
    summary.add_row("Puertos abiertos:", f"[green]{len(open_ports)}[/green]")
    if critical_ports:
        summary.add_row("Puertos críticos:", f"[red]{', '.join(map(str, critical_ports))}[/red]")
    
    console.print(Panel(summary, title="[bold]Resumen del Escaneo[/bold]", border_style="blue"))
    
    # Tabla de puertos abiertos
    if open_ports:
        table = Table(title="[bold]Puertos Abiertos[/bold]", box=box.ROUNDED)
        table.add_column("Puerto", justify="center")
        table.add_column("Estado")
        table.add_column("Servicio")
        table.add_column("Seguridad")
        
        for port in sorted(open_ports):
            if port in CRITICAL_PORTS:
                status = "[red]CRÍTICO[/red]"
                service = "[red]Verificar inmediatamente[/red]"
            elif port in SAFE_PORTS:
                status = "[green]SEGURO[/green]"
                service = "[green]Normal[/green]"
            else:
                status = "[yellow]ADVERTENCIA[/yellow]"
                service = "[yellow]Revisar[/yellow]"
            
            table.add_row(
                str(port),
                "[green]ABIERTO[/green]",
                service,
                status
            )
        
        console.print(table)
    
    # Mostrar cambios desde el último escaneo
    changes = scan_data.get('changes', {})
    if changes:
        changes_table = Table(title="[bold]Cambios desde el último escaneo[/bold]", box=box.ROUNDED)
        changes_table.add_column("Tipo")
        changes_table.add_column("Puertos")
        
        if changes.get('added'):
            added_ports = ", ".join(map(str, changes['added']))
            changes_table.add_row("[green]Agregados[/green]", f"[green]{added_ports}[/green]")
        
        if changes.get('removed'):
            removed_ports = ", ".join(map(str, changes['removed']))
            changes_table.add_row("[red]Eliminados[/red]", f"[red]{removed_ports}[/red]")
        
        console.print(changes_table)

def print_scan_history(scans: List[Dict[str, Any]]):
    """Muestra el historial de escaneos."""
    if not scans:
        console.print("[yellow]No hay escaneos registrados.[/yellow]")
        return
    
    table = Table(title="[bold]Historial de Escaneos[/bold]", box=box.ROUNDED)
    table.add_column("ID", justify="right")
    table.add_column("Objetivo")
    table.add_column("Fecha")
    table.add_column("Puertos Abiertos", justify="center")
    table.add_column("Duración (s)", justify="right")
    
    for scan in scans:
        timestamp = scan.get('timestamp', 'N/A')
        if isinstance(timestamp, str) and 'T' in timestamp:
            # Formatear timestamp ISO 8601 a algo más legible
            date_part, time_part = timestamp.split('T')
            time_part = time_part.split('.')[0]  # Eliminar milisegundos
            formatted_time = f"{date_part} {time_part}"
        else:
            formatted_time = str(timestamp)
        
        table.add_row(
            str(scan.get('id', 'N/A')),
            scan.get('ip', 'N/A'),
            formatted_time,
            str(scan.get('open_ports_count', 0)),
            f"{scan.get('duration_seconds', 0):.2f}" if 'duration_seconds' in scan else 'N/A'
        )
    
    console.print(table)

def confirm_action(prompt: str, default: bool = False) -> bool:
    """Solicita confirmación al usuario."""
    try:
        response = input(f"{prompt} (s/n) [{'s' if default else 'n'}] ").strip().lower()
        if not response:
            return default
        return response in ('s', 'si', 'sí')
    except (KeyboardInterrupt, EOFError):
        return False

def main():
    """Función principal de la interfaz de línea de comandos."""
    # Configuración del parser de argumentos
    parser = argparse.ArgumentParser(description='Escáner de Puertos Mejorado')
    parser.add_argument('command', nargs='?', help='Comando a ejecutar')
    parser.add_argument('args', nargs=argparse.REMAINDER, help='Argumentos del comando')
    
    # Mostrar banner
    print_banner()
    
    # Inicializar el escáner
    scanner = PortScanner()
    
    # Bucle principal de la interfaz
    while True:
        try:
            # Si no hay argumentos, mostrar prompt interactivo
            if not hasattr(main, 'already_run'):
                main.already_run = True
                if len(sys.argv) > 1:
                    # Modo no interactivo con argumentos
                    command = sys.argv[1]
                    args = sys.argv[2:]
                else:
                    # Modo interactivo
                    command = input("\n[bold blue]portscan>[/bold blue] ").strip()
                    if not command:
                        continue
                    
                    # Parsear el comando
                    parts = command.split()
                    command = parts[0]
                    args = parts[1:]
            else:
                # Modo interactivo continuo
                command = input("\n[bold blue]portscan>[/bold blue] ").strip()
                if not command:
                    continue
                
                # Parsear el comando
                parts = command.split()
                command = parts[0]
                args = parts[1:]
            
            # Procesar comandos
            if command in ('exit', 'quit'):
                console.print("[yellow]Saliendo del escáner...[/yellow]")
                break
                
            elif command == 'help':
                print_help()
                
            elif command == 'safe-ports':
                print_safe_ports()
                
            elif command == 'critical-ports':
                print_critical_ports()
                
            elif command == 'scan':
                target = args[0] if args else None
                ports = None
                
                # Parsear argumentos adicionales
                if '--ports' in args:
                    idx = args.index('--ports')
                    if idx + 1 < len(args):
                        try:
                            ports = [int(p) for p in args[idx+1].split(',')]
                        except ValueError:
                            console.print("[red]Error:[/red] Los puertos deben ser números separados por comas")
                            continue
                
                console.print(f"[bold]Iniciando escaneo de {target or 'red local'}...[/bold]")
                result = scanner.scan_and_compare(target=target, ports=ports)
                print_scan_results(result)
                
            elif command == 'rescan':
                if not scanner.last_scan:
                    console.print("[yellow]No hay un escaneo previo para repetir.[/yellow]")
                    continue
                    
                target = scanner.last_scan.get('target')
                console.print(f"[bold]Repitiendo último escaneo de {target}...[/bold]")
                result = scanner.scan_and_compare(target=target)
                print_scan_results(result)
                
            elif command == 'portcheck':
                if len(args) < 2:
                    console.print("[red]Uso: portcheck IP PUERTO[/red]")
                    continue
                    
                target = args[0]
                try:
                    port = int(args[1])
                except ValueError:
                    console.print("[red]Error:[/red] El puerto debe ser un número")
                    continue
                    
                result = scanner.get_port_status(target, port)
                if result.get('success', False):
                    status = "[green]ABIERTO[/green]" if result['is_open'] else "[red]CERRADO[/red]"
                    security = "[green]SEGURO[/green]" if result['is_safe'] else "[red]ADVERTENCIA:[/red]"
                    
                    table = Table(box=box.ROUNDED)
                    table.add_column("Campo", style="cyan")
                    table.add_column("Valor")
                    
                    table.add_row("Objetivo:", target)
                    table.add_row("Puerto:", str(port))
                    table.add_row("Estado:", status)
                    table.add_row("Seguridad:", security)
                    
                    if result['is_critical']:
                        table.add_row("Importancia:", "[red]CRÍTICO[/red] - Este puerto es esencial para la seguridad del sistema")
                    
                    console.print(table)
                else:
                    console.print(f"[red]Error:[/red] {result.get('error', 'Error desconocido')}")
                    
            elif command == 'history':
                target = args[0] if args else None
                scans = scanner.db.get_all_scans(ip=target)
                print_scan_history(scans)
                
            elif command == 'show':
                if not args:
                    console.print("[red]Uso: show SCAN_ID[/red]")
                    continue
                    
                try:
                    scan_id = int(args[0])
                    # Aquí iría la lógica para mostrar un escaneo específico
                    console.print(f"[yellow]Mostrando detalles del escaneo {scan_id}...[/yellow]")
                    # Implementar lógica para mostrar detalles del escaneo
                except ValueError:
                    console.print("[red]Error:[/red] El ID del escaneo debe ser un número")
                    
            elif command == 'search':
                # Parsear argumentos de búsqueda
                search_args = {}
                i = 0
                while i < len(args):
                    if args[i] == '--ip' and i + 1 < len(args):
                        search_args['ip'] = args[i+1]
                        i += 2
                    elif args[i] == '--port' and i + 1 < len(args):
                        try:
                            search_args['port'] = int(args[i+1])
                            i += 2
                        except ValueError:
                            console.print("[red]Error:[/red] El puerto debe ser un número")
                            i += 2
                            continue
                    else:
                        i += 1
                
                results = scanner.search_scans(**search_args)
                if results:
                    console.print(f"[green]Se encontraron {len(results)} resultados:[/green]")
                    print_scan_history(results)
                else:
                    console.print("[yellow]No se encontraron resultados para la búsqueda.[/yellow]")
                    
            else:
                console.print(f"[red]Comando no reconocido: {command}[/red]")
                console.print("Escribe 'help' para ver los comandos disponibles.")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Operación cancelada por el usuario.[/yellow]")
            continue
            
        except Exception as e:
            console.print(f"[red]Error:[/red] {str(e)}")
            if hasattr(e, '__traceback__'):
                import traceback
                console.print(traceback.format_exc())

if __name__ == "__main__":
    main()
