from rich.console import Console
from rich.table import Table
from rich.text import Text
from advancedTable import AdvancedTable
from ui import navigate, draw_table

import nmap_module as nmap

def create_modes_table():
    title = Text("Pentesting tool - Modes")
    title.stylize("bold red")
    table = Table(title=title, style="red")

    table.add_column("Mode", justify="left", style="bold white", no_wrap=True)
    table.add_column("Info", style="magenta")

    table.add_row("Nmap", "Gebruik verschillende nmap funcionaliteiten om een host te scannen")
    table.add_row("XSS", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Platea. Volutpat. Auctor.")
    table.add_row("SQL injection", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Consectetur. Luctus. Class. Sodales. Pharetra.")
    table.add_row("Certificate check", "Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
    table.add_row("Brute force", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus mauris nostra dignissim nostra lorem mus.")
    
    functions = [
        nmap.load
    ]

    advancedTable = AdvancedTable(table, functions)
    navigate(advancedTable)

if __name__ == "__main__":
    create_modes_table()

