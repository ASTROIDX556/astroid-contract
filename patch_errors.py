with open("shared/src/errors.rs", "r") as f:
    text = f.read()

text = text.replace("PolicyRecipientRestricted = 23,", "PolicyRecipientRestricted = 23,\n    AssetRestricted = 24,\n    LimitExceeded = 25,\n    OutOfWindow = 26,")

with open("shared/src/errors.rs", "w") as f:
    f.write(text)
