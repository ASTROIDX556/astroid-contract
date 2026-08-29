import re
with open("shared/src/errors.rs", "r") as f:
    c = f.read()
c = c.replace("PolicyCategoryRestricted = 25,", "PolicyCategoryRestricted = 25,\n    Test1 = 26,\n    Test2 = 27,\n    Test3 = 28,")
with open("shared/src/errors.rs", "w") as f:
    f.write(c)
