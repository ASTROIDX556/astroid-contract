import re

# 1. Fix budget test
with open("contracts/budget/src/test.rs", "r") as f:
    bt = f.read()

# Replace the conflict marker for budget test, keeping both blocks
bt = re.sub(
    r"<<<<<<< HEAD\n([\s\S]*?)=======\n([\s\S]*?)>>>>>>> origin/main",
    r"\1\n\2",
    bt
)
with open("contracts/budget/src/test.rs", "w") as f:
    f.write(bt)


# 2. Fix wallet lib
with open("contracts/wallet/src/lib.rs", "r") as f:
    wl = f.read()

# In wallet lib, we want to discard HEAD's `ensure!` refactor for the conflicting blocks
# and KEEP origin/main's RBAC code.
wl = re.sub(
    r"<<<<<<< HEAD\n([\s\S]*?)=======\n([\s\S]*?)>>>>>>> origin/main",
    r"\2",
    wl
)
with open("contracts/wallet/src/lib.rs", "w") as f:
    f.write(wl)

