---
description: Basic example
icon: python
---

# antikeylogger



```
#!/usr/bin/env python3

import psutil # pip install psutil

def find_suspicious_processes():
    suspicious_keywords = [
        "pynput", 
        "keylogger", 
        "keyboard_listener",
        "log_keys.py"
    ]
    
    found_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Check the process name and its command line arguments
            process_info = proc.info
            cmdline = " ".join(process_info['cmdline']).lower() if process_info['cmdline'] else ""
            name = process_info['name'].lower()

            # Look for any suspicious keywords
            for keyword in suspicious_keywords:
                if keyword in name or keyword in cmdline:
                    found_processes.append({
                        'pid': process_info['pid'],
                        'name': name,
                        'cmdline': cmdline
                    })
                    break # Found one, no need to check other keywords for this process

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Skip processes that disappear or we can't access
            pass

    return found_processes

if __name__ == "__main__":
    print("[*] Hunting for suspicious keylogger processes...")
    suspicious = find_suspicious_processes()

    if suspicious:
        print("[!] Potential Keyloggers Found!")
        for proc in suspicious:
            print(f"    PID: {proc['pid']} | Name: {proc['name']}")
            # Optional: Add code here to AUTO-KILL the process
            # *nix example
            import os
            os.kill(proc['pid'], 9)
            print(f"      -> Process {proc['pid']} terminated.")
    else:
        print("[+] No obvious keyloggers found. System appears clean.")



```
