import re
with open("shared/src/errors.rs", "r") as f:
    c = f.read()

# I will just keep origin/main and append PR 73's errors at the end (but ensuring <= 50)
c = re.sub(r"<<<<<<< HEAD\n(.*?)\n=======\n(.*?)\n>>>>>>> origin/main", r"\1\n\2", c, flags=re.DOTALL)
with open("shared/src/errors.rs", "w") as f:
    f.write(c)

with open("shared/src/lib.rs", "r") as f:
    c = f.read()

c = re.sub(r"<<<<<<< HEAD\n(.*?)\n=======\n(.*?)\n>>>>>>> origin/main", r"\1\n\2", c, flags=re.DOTALL)
with open("shared/src/lib.rs", "w") as f:
    f.write(c)

with open("shared/src/test.rs", "r") as f:
    c = f.read()

c = re.sub(r"<<<<<<< HEAD\n(.*?)\n=======\n(.*?)\n>>>>>>> origin/main", r"\1\n\2", c, flags=re.DOTALL)
with open("shared/src/test.rs", "w") as f:
    f.write(c)
