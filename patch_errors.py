with open("shared/src/errors.rs", "r") as f:
    text = f.read()
<<<<<<< HEAD
if "FeeLimitExceeded" not in text:
    text = text.replace("PolicyRecipientRestricted = 23,", "PolicyRecipientRestricted = 23,\n    FeeLimitExceeded = 24,")
=======

text = text.replace("NotAnApprover = 73,", "NotAnApprover = 73,\n    CancellationWindowClosed = 74,\n    MathOverflow = 75,\n    DivisionByZero = 76,")

>>>>>>> origin/main
with open("shared/src/errors.rs", "w") as f:
    f.write(text)
