import re

with open("contracts/budget/src/lib.rs", "r") as f:
    text = f.read()

text = text.replace("budget.spent = checked_sub(budget.spent, amount)?;", "if budget.spent < amount { return Err(Error::Underflow); }\n        budget.spent = checked_sub(budget.spent, amount)?;")

with open("contracts/budget/src/lib.rs", "w") as f:
    f.write(text)
