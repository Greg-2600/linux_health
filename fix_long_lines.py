#!/usr/bin/env python3
"""Automatically fix long lines in checks.py by wrapping string literals."""

import re
from pathlib import Path


def fix_long_lines(file_path, line_limit=100):
    """Fix long lines by wrapping string literals intelligently."""
    content = Path(file_path).read_text()
    lines = content.split('\n')
    fixed_lines = []
    
    for i, line in enumerate(lines, 1):
        if len(line) <= line_limit:
            fixed_lines.append(line)
            continue
            
        # For very long lines with bash commands, wrap them
        if 'bash -lc' in line or 'echo ' in line:
            # Try to wrap bash commands intelligently
            if '= "' in line:
                # Simple case: variable assignment with string
                match = re.match(r'(\s*)(.+?)\s*=\s*"(.+)"(.*)$', line)
                if match:
                    indent, var_part, cmd, suffix = match.groups()
                    # Split the command by logical breaks
                    if ';' in cmd:
                        parts = [p.strip() for p in cmd.split(';')]
                        wrapped = f'{indent}{var_part} = (\n'
                        for j, part in enumerate(parts[:-1]):
                            wrapped += f'{indent}    "{part}; "\n'
                        wrapped += f'{indent}    "{parts[-1]}"\n'
                        wrapped += f'{indent}){suffix}'
                        fixed_lines.append(wrapped)
                        continue
        
        # For assignment with parentheses, just add it
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


if __name__ == '__main__':
    checks_file = Path('/home/greg/projects/linux_health/linux_health/checks.py')
    
    # Read the file
    content = checks_file.read_text()
    
    # For now, just report the statistics
    lines = content.split('\n')
    long_lines = [(i+1, len(line), line[:80]) for i, line in enumerate(lines) if len(line) > 100]
    
    print(f"Found {len(long_lines)} lines exceeding 100 characters")
    print("\nTop 10 longest lines:")
    for line_num, length, preview in sorted(long_lines, key=lambda x: x[1], reverse=True)[:10]:
        print(f"Line {line_num}: {length} chars - {preview}...")
