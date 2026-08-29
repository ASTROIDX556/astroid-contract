import re
with open("contracts/policy/src/lib.rs", "r") as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    if "<<<<<<< HEAD" in lines[i]:
        while "=======" not in lines[i]:
            new_lines.append(lines[i])
            i += 1
        i += 1
        while ">>>>>>> origin/main" not in lines[i]:
            new_lines.append(lines[i])
            i += 1
    else:
        new_lines.append(lines[i])
    i += 1

with open("contracts/policy/src/lib.rs", "w") as f:
    f.write("".join(new_lines).replace("<<<<<<< HEAD\n", "").replace("=======\n", "").replace(">>>>>>> origin/main\n", ""))

with open("contracts/policy/src/test.rs", "r") as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    if "<<<<<<< HEAD" in lines[i]:
        while "=======" not in lines[i]:
            new_lines.append(lines[i])
            i += 1
        i += 1
        while ">>>>>>> origin/main" not in lines[i]:
            new_lines.append(lines[i])
            i += 1
    else:
        new_lines.append(lines[i])
    i += 1

with open("contracts/policy/src/test.rs", "w") as f:
    f.write("".join(new_lines).replace("<<<<<<< HEAD\n", "").replace("=======\n", "").replace(">>>>>>> origin/main\n", ""))

