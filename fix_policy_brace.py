with open("contracts/policy/src/lib.rs", "r") as f:
    c = f.read()
c = c.replace("mod test;", "}\nmod test;")
with open("contracts/policy/src/lib.rs", "w") as f:
    f.write(c)
