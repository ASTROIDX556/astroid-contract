import re

with open("shared/src/errors.rs", "r") as f:
    c = f.read()

lines = c.split("\n")
new_lines = []
val = 1
for line in lines:
    if " = " in line and "," in line:
        parts = line.split(" = ")
        new_lines.append(parts[0] + f" = {val},")
        val += 1
    else:
        new_lines.append(line)

with open("shared/src/errors.rs", "w") as f:
    f.write("\n".join(new_lines))
