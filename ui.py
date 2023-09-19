from rich.console import Console
from rich.table import Table
from rich.text import Text
from advancedTable import AdvancedTable
import keyboard
import os


def draw_table(table: Table, active_index: int):
    from rich.console import Console
    os.system("clear")
    for index in range(0,len(table.rows)):
        if index != active_index:
            table.rows[index].style="white"
        else:
            table.rows[index].style="bold white on red"
    Console().print(table)

def navigate(table: AdvancedTable):

    while True:
        draw_table(table.layout, table.activeRowIndex)
        keyboard.read_event()
        if keyboard.is_pressed("up"):
            table.activeRowIndex = (table.activeRowIndex - 1) % len(table.layout.rows)
        elif keyboard.is_pressed("down"):
            table.activeRowIndex = (table.activeRowIndex + 1) % len(table.layout.rows)
        elif keyboard.is_pressed("enter"):
            table.activate_function()
        elif keyboard.is_pressed("q"):
            exit()