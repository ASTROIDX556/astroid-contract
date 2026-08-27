with open("shared/src/errors.rs", "r") as f:
    text = f.read()
if "FeeLimitExceeded" not in text:
    text = text.replace("PolicyRecipientRestricted = 23,", "PolicyRecipientRestricted = 23,\n    FeeLimitExceeded = 24,")
with open("shared/src/errors.rs", "w") as f:
    f.write(text)
