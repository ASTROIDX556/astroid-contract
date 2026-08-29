import re
with open("shared/src/errors.rs", "r") as f:
    c = f.read()

# Remove unused variants
unused = ["PolicyHashMismatch", "InvalidSignature", "ConditionNotMet", "EscrowNotFunded", "InvalidCondition", "InvalidDeadline", "InvalidDeposit"]
for u in unused:
    c = re.sub(r"    " + u + r" = \d+,\n", "", c)

with open("shared/src/errors.rs", "w") as f:
    f.write(c)
