import re
with open("shared/src/errors.rs", "r") as f:
    text = f.read()

replacement = """    PolicyDenied = 20,
    PolicyHashMismatch = 21,
    EmergencyLock = 22,
    PolicyRecipientRestricted = 23,
    PolicyMerchantBlocked = 24,
    PolicyCategoryRestricted = 25,
    /// The asset is not in the organization's whitelist.
    AssetNotWhitelisted = 26,
    FeeLimitExceeded = 27,"""

text = re.sub(
    r"<<<<<<< HEAD\n([\s\S]*?)=======\n([\s\S]*?)>>>>>>> origin/main",
    replacement,
    text
)
with open("shared/src/errors.rs", "w") as f:
    f.write(text)

