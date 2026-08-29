import re

with open("contracts/proposal/src/test.rs", "r") as f:
    text = f.read()

<<<<<<< HEAD
# Replace client.create with 3 more args: deadline, Option<Address>, i128
text = re.sub(r"(&env,\n\s*&1,\n\s*&0,\n\s*\))", r"&env,\n        &1,\n        &0,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&1,\n\s*&0,\n\s*\))", r"&h.approvers,\n        &1,\n        &0,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&2,\n\s*&0,\n\s*\))", r"&h.approvers,\n        &2,\n        &0,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&3,\n\s*&0,\n\s*\))", r"&h.approvers,\n        &3,\n        &0,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&0,\n\s*&0,\n\s*\))", r"&h.approvers,\n        &0,\n        &0,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&5,\n\s*&0,\n\s*\))", r"&h.approvers,\n        &5,\n        &0,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&1,\n\s*&500,\n\s*\))", r"&h.approvers,\n        &1,\n        &500,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&1,\n\s*&expires_at,\n\s*\))", r"&h.approvers,\n        &1,\n        &expires_at,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&2,\n\s*&1500,\n\s*\))", r"&h.approvers,\n        &2,\n        &1500,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&h\.approvers,\n\s*&2,\n\s*&expires_at,\n\s*\))", r"&h.approvers,\n        &2,\n        &expires_at,\n        &None,\n        &0,\n    )", text)
text = re.sub(r"(&env, &1, &0\))", r"&env, &1, &0, &None, &0)", text)

text = text.replace("h.client.expire(&id);", "h.client.claim_expired_refund(&id);")
text = text.replace("h.client.try_expire(&id)", "h.client.try_claim_expired_refund(&id)")
text = text.replace("fn explicit_expire_transition", "fn test_claim_expired_refund")

# The mock is missing the arguments
text = re.sub(r"(&1, &0\))", r"&1, &0, &None, &0)", text)
=======
# Fix the try_create calls missing the 9th argument
text = text.replace("""        &5_000,
    );""", """        &5_000,
        &0,
    );""")

text = text.replace("""        &500, // in the past (now = 1000)
    );""", """        &500, // in the past (now = 1000)
        &0,
    );""")

text = text.replace("""        &expires_at,
    )""", """        &expires_at,
        &0,
    )""")

# Fix &h.approvers -> &approver_vec(&h)
text = text.replace("&h.approvers,", "&approver_vec(&h),")
>>>>>>> origin/main

with open("contracts/proposal/src/test.rs", "w") as f:
    f.write(text)
