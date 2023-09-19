# Definieer een functie met parameters
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}!"

# Maak een lambda-functie die de parameters doorgeeft
greeting_function = lambda name: greet(name, "Hi")

# Roep de lambda-functie op
result = greeting_function("Alice")

# Druk het resultaat af
print(result)  # Dit zal "Hi, Alice!" afdrukken
