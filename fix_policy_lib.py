with open("contracts/policy/src/lib.rs", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if line.strip() == "mod test;":
        new_lines.append("}\nmod test;\n")
    else:
        new_lines.append(line)

with open("contracts/policy/src/lib.rs", "w") as f:
    f.write("".join(new_lines))
