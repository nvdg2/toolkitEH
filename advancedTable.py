from rich.table import Table
class AdvancedTable:
    def __init__(self, table_layout: Table, functions: list):
        self.layout = table_layout
        self.functions=functions
        self.activeRowIndex = 0

    def activate_function(self):
        self.functions[self.activeRowIndex]()
        exit()