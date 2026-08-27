import re
with open("contracts/treasury/src/lib.rs", "r") as f:
    text = f.read()

text = text.replace("return Err(Error::InvalidAction); // Or reentrancy error", "return Err(Error::InvalidState);")

with open("contracts/treasury/src/lib.rs", "w") as f:
    f.write(text)
