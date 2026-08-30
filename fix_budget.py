import re
with open("contracts/budget/src/test.rs", "r") as f:
    bt = f.read()

bt = re.sub(
    r"<<<<<<< HEAD\n([\s\S]*?)=======\n([\s\S]*?)>>>>>>> origin/main",
    r"\1\n\2",
    bt
)
with open("contracts/budget/src/test.rs", "w") as f:
    f.write(bt)

