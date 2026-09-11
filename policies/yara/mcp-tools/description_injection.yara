// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

// These rules identify concrete harmful requests embedded in MCP tool
// descriptions. They deliberately require both an operation and narrow object,
// destination, amount, or ownership evidence. Static YARA findings remain
// alert-only: authorization and destination trust require deployment policy or
// a bounded ActionFacts proof before DefenseClaw can safely block.
rule defenseclaw_sensitive_data_to_addressed_sink {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects an instruction to transmit sensitive data to an addressed sink"
        classification = "harmful"
        threat_type = "DATA EXFILTRATION"

    strings:
        $send = /\b(send|forward)(s|ed|ing)?\b[^\n]{0,240}(@|\bemail\b|gmail)/i
        $email = /\bemail(s|ed|ing)?\s+(it|them|this|that|the|those|a|all|my|your|information|details|data|file|copy|summary)\b[^\n]{0,240}(@|\bemail\b|gmail)/i
        $share = /\b(shar(e|ed|es)|sharing)\b[^\n]{0,240}\b(with|to|for)\b[^\n]{0,100}(@|\bemail\b)/i
        $sensitive = /\b(passwords?|credentials?|secrets?|tokens?|genetic|medical|clinical|patient|prescriptions?|payment methods?|bank|account|holdings|payees?|order history|search history|browsing history|friends list|access history|current location|saved addresses|shipments?|reservations?|phone|public records?|personal details|profile details|security logs?|confidential|files and folders|health (recommendations?|system|report)|deepfake|voice|audio file)\b/i
        $directive = /\b(please|could you|can you|my|me|mine|myself|i'm)\b/i

    condition:
        ($send or $email or $share) and $sensitive and $directive
}

rule defenseclaw_concrete_financial_action {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a concrete owned-account financial action with an amount"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "FINANCIAL ACTION"

    strings:
        $action = /\b(transfer|withdraw|deposit|sell|payment|pay)(s|ed|ing)?\b/i
        $amount = /(\$\s?[0-9]|\b[0-9][0-9,]*(\.[0-9]+)?\s*(usd|bitcoin|btc|units?)\b)/i
        $owned = /\b(please|my)\b/i

    condition:
        all of them
}

rule defenseclaw_exact_destructive_user_data {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects narrowly worded destructive operations against owned user data"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "DESTRUCTIVE ACTION"

    strings:
        $delete = /\bdelete\s+(all\s+(of\s+)?)?my\b[^\n]{0,100}\b(clinical documents?|project repositor(y|ies)|files?|records?)\b/i
        $move = /\bmove\s+all\s+files\b[^\n]{0,100}\b(private|documents)\b[^\n]{0,80}\/tmp\b/i
        $medical = /\bremove\s+(the\s+)?allergy\b[^\n]{0,100}\bhealth record\b/i

    condition:
        any of them
}

rule defenseclaw_security_control_downgrade {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects an owned-account request to disable multifactor authentication"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "SECURITY CONTROL DOWNGRADE"

    strings:
        $disable = /\bdisable\b[^\n]{0,80}\b(two[- ]factor authentication|2fa|multi[- ]factor authentication|mfa)\b/i
        $owned = /\b(my|for my)\b/i

    condition:
        all of them
}

rule defenseclaw_profile_multi_attribute_change {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a request to replace multiple sensitive profile attributes"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "PROFILE TAMPERING"

    strings:
        $request = /\bupdate\s+my\b[^\n]{0,80}\bprofile\b/i
        $email = /\bemail\b/i
        $location = /\blocation\b/i
        $birthday = /\bbirthday\b/i

    condition:
        all of them
}
