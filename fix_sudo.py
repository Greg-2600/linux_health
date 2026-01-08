#!/usr/bin/env python3
import re

with open('linux_health/checks.py', 'r') as f:
    content = f.read()

# Remove echo password pattern for sudo commands
# Pattern 1: f"echo '{password}' | sudo -S
content = re.sub(
    r"""f"echo \'{password}\' \| sudo -S""",
    r'f"sudo -S',
    content
)

# Pattern 2: echo '{password}' | sudo -S 
content = content.replace("echo '{password}' | sudo -S", "sudo -S")

# Pattern 3: echo '{password}' | sudo -n -S (if any remain)
content = content.replace("echo '{password}' | sudo -n -S", "sudo -S")

with open('linux_health/checks.py', 'w') as f:
    f.write(content)

print('Replacements complete')
