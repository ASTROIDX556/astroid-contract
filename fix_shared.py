import re
with open("shared/src/test.rs", "r") as f:
    text = f.read()

text = re.sub(
    r"<<<<<<< HEAD\n([\s\S]*?)=======\n([\s\S]*?)>>>>>>> origin/main",
    r"\2",
    text
)
with open("shared/src/test.rs", "w") as f:
    f.write(text)

