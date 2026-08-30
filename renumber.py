import re

with open('shared/src/errors.rs', 'r') as f:
    lines = f.readlines()

out_lines = []
counter = 1
for line in lines:
    if '=' in line and ',' in line:
        line = re.sub(r'=\s*\d+', f'= {counter}', line)
        counter += 1
    out_lines.append(line)

with open('shared/src/errors.rs', 'w') as f:
    f.writelines(out_lines)
