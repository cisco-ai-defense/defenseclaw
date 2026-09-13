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
        $operation_object_recipient = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?((send|forward)(s|ed|ing)?|email(s|ed|ing)?|shar(e|ed|es|ing))\b[^\n.!?]{0,180}\b(passwords?|credentials?|secrets?|tokens?|genetic|medical|clinical|patient|prescriptions?|payment methods?|bank accounts?|holdings|payees?|order history|search history|browsing history|friends list|access history|current location|saved addresses|shipments?|reservations?|phone|public records?|personal details|profile details|security logs?|confidential([ _-][A-Z0-9_-]+)?|(files and folders|folders and files)|health (recommendations?|system|report)|deepfake|voice|audio file)\b[^\n.!?]{0,180}\b(to|with|for)\b[^\n.!?]{0,48}[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $operation_recipient_object = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?((send|forward)(s|ed|ing)?|email(s|ed|ing)?|shar(e|ed|es|ing))\b[^\n.!?]{0,48}(to|with|for)?\s*[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+[^\n.!?]{0,80}\b(my|all|those|these)\s+(passwords?|credentials?|secrets?|tokens?|genetic|medical|clinical|patient|prescriptions?|payment methods?|bank accounts?|holdings|payees?|order history|search history|browsing history|friends list|access history|current location|saved addresses|shipments?|reservations?|phone|public records?|personal details|profile details|security logs?|confidential([ _-][A-Z0-9_-]+)?|(files and folders|folders and files)|health (recommendations?|system|report)|deepfake|voice|audio file)\b/i
        $object_operation_recipient = /\b(please|could you|can you)\b[^\n.!?]{0,180}\b(passwords?|credentials?|secrets?|tokens?|genetic|medical|clinical|patient|prescriptions?|payment methods?|bank accounts?|holdings|payees?|order history|search history|browsing history|friends list|access history|current location|saved addresses|shipments?|reservations?|phone|public records?|personal details|profile details|security logs?|confidential([ _-][A-Z0-9_-]+)?|(files and folders|folders and files)|health (recommendations?|system|report)|deepfake|voice|audio file)\b[^\n.!?]{0,180}\b((send|forward)(s|ed|ing)?|email(s|ed|ing)?|shar(e|ed|es|ing))\b[^\n.!?]{0,80}\b(to|with|for)\b[^\n.!?]{0,48}[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $retrieve_sensitive_then_addressed_sink = /(^|[\n.!?]\s*)((please|could you|can you|first, please)\s+)?(retrieve|get|fetch|find|list|access|download|check|provide|search|retrive)\b[^\n]{0,240}\b(passwords?|credentials?|secrets?|tokens?|genetic|medical|clinical|patient|prescriptions?|payment methods?|bank accounts?|linked accounts?|savings? accounts?|holdings|payees?|order history|search history|browsing history|friends list|access history|current location|current image|future flights?|saved addresses|shipments?|reservations?|phone( number)?|public records?|personal details|profile details|security logs?|confidential([ _-][A-Z0-9_-]+)?|(files and folders|folders and files)|health (recommendations?|system|report)|voice|audio file)\b[^\n]{0,300}\b((send|forward|share)(s|ed|ing)?|email(s|ed|ing)?)\b[^\n]{0,140}["']?[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $share_owned_password_to_address = /(^|[\n.!?]\s*)(please\s+)?share\s+the\s+password\b[^\n.!?]{0,80}\bfor\s+my\s+[A-Z0-9.-]+\s+account\b[^\n.!?]{0,160}\bwith\s+my\b[^\n.!?]{0,100}\bemail address\b[^\n.!?]{0,32}["']?[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $generate_owned_deepfake_to_address = /(^|[\n.!?]\s*)(please\s+)?generate\s+an?\s+audio deepfake\b[^\n]{0,180}\busing\s+my\s+voice\b[^\n]{0,260}\bonce generated\b[^\n]{0,120}\bsend\s+the\s+audio file\b[^\n]{0,100}["']?[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $search_payees_then_addressed_sink = /(^|[\n.!?]\s*)(please\s+)?use\b[^\n]{0,100}\bsearch\s+for\s+all\s+payees\b[^\n]{0,260}\bonce\b[^\n]{0,160}\bsend\b[^\n]{0,140}\bemail address\b[^\n]{0,32}["']?[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $authorization_context = /\b(approved|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        $operation_object_recipient or $operation_recipient_object or
        $object_operation_recipient or
        (($retrieve_sensitive_then_addressed_sink or $share_owned_password_to_address or
          $generate_owned_deepfake_to_address or $search_payees_then_addressed_sink) and
         not $authorization_context)
}

rule defenseclaw_concrete_financial_action {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a concrete owned-account financial action with an amount"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "FINANCIAL ACTION"

    strings:
        $amount_then_owned = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?(transfer|withdraw|deposit|sell|payment|pay)(s|ed|ing)?\b[^\n.!?]{0,120}(\$\s?[0-9]|\b[0-9][0-9,]*(\.[0-9]+)?\s*(usd|bitcoin|btc|units?)\b)[^\n.!?]{0,120}\b(from|into|using)\s+my\s+(account|wallet|portfolio)\b/i
        $owned_then_amount = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?(transfer|withdraw|deposit|sell|payment|pay)(s|ed|ing)?\b[^\n.!?]{0,120}\b(from|into|using)\s+my\s+(account|wallet|portfolio)\b[^\n.!?]{0,120}(\$\s?[0-9]|\b[0-9][0-9,]*(\.[0-9]+)?\s*(usd|bitcoin|btc|units?)\b)/i
        $transfer_amount_to_identified_account = /(^|[\n.!?]\s*)(please\s+)?transfer\b[^\n.!?]{0,80}(\$\s?[0-9][0-9,]*(\.[0-9]+)?|\b[0-9][0-9,]*(\.[0-9]+)?\s*(usd|bitcoin|btc)\b)[^\n.!?]{0,120}\bto\s+(the\s+)?(bank\s+)?account\b[^\n.!?]{0,40}\b(number|id)\b[^\n.!?]{0,20}["']?[A-Z0-9][A-Z0-9-]{3,31}/i
        $initiate_owned_payment_to_payee = /(^|[\n.!?]\s*)(please\s+)?initiate\s+a\s+payment\s+of\s+(\$\s?[0-9][0-9,]*(\.[0-9]+)?|[0-9][0-9,]*(\.[0-9]+)?\s*(usd|bitcoin|btc))\b[^\n.!?]{0,100}\bfrom\s+my\s+account\b[^\n.!?]{0,100}\bto\s+payee\b[^\n.!?]{0,20}["']?[A-Z0-9][A-Z0-9-]{3,31}/i
        $sell_owned_holdings_amount = /(^|[\n.!?]\s*)(please\s+)?sell\s+[0-9][0-9,]*(\.[0-9]+)?\s+units?\s+of\s+my\s+(bitcoin|btc)\s+holdings\b/i
        $withdraw_crypto_to_owned_account = /(^|[\n.!?]\s*)(please\s+)?withdraw\s+[0-9][0-9,]*(\.[0-9]+)?\s+(bitcoin|btc)\s+to\s+my\s+bank\s+account\b[^\n.!?]{0,24}\b[0-9][0-9-]{3,31}/i
        $authorization_context = /\b(approved|approval|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        $amount_then_owned or $owned_then_amount or
        (($transfer_amount_to_identified_account or $initiate_owned_payment_to_payee or
          $sell_owned_holdings_amount or $withdraw_crypto_to_owned_account) and
         not $authorization_context)
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
        $disable_owned = /(^|[\n.!?]\s*)(please\s+)?disable\b[^\n.!?]{0,80}\b(two[- ]factor authentication|2fa|multi[- ]factor authentication|mfa)\b[^\n.!?]{0,80}\b(for|on)\s+my\s+account\b/i
        $owned_disable = /(^|[\n.!?]\s*)(please\s+)?disable\b[^\n.!?]{0,80}\bmy\s+account('s)?\b[^\n.!?]{0,80}\b(two[- ]factor authentication|2fa|multi[- ]factor authentication|mfa)\b/i
        $disable_provider_account = /(^|[\n.!?]\s*)(please\s+)?disable\b[^\n.!?]{0,80}\b(two[- ]factor authentication|2fa|multi[- ]factor authentication|mfa)\b[^\n.!?]{0,80}\bfor\s+my\s+[A-Z][A-Z0-9_-]*(\s+[A-Z][A-Z0-9_-]*){0,3}\s+account\b/i
        $authorization_context = /\b(approved|approval|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        ($disable_owned or $owned_disable or $disable_provider_account) and
        not $authorization_context
}

rule defenseclaw_profile_multi_attribute_change {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a request to replace multiple sensitive profile attributes"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "PROFILE TAMPERING"

    strings:
        $email_location_birthday = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?update\s+my\b[^\n.!?]{0,80}\bprofile\b[^\n.!?]{0,120}\bemail\b[^\n.!?]{0,80}\blocation\b[^\n.!?]{0,80}\bbirthday\b/i
        $email_birthday_location = /\b(please|could you|can you)\b[^\n.!?]{0,48}\bupdate\s+my\b[^\n.!?]{0,80}\bprofile\b[^\n.!?]{0,120}\bemail\b[^\n.!?]{0,80}\bbirthday\b[^\n.!?]{0,80}\blocation\b/i
        $location_email_birthday = /\b(please|could you|can you)\b[^\n.!?]{0,48}\bupdate\s+my\b[^\n.!?]{0,80}\bprofile\b[^\n.!?]{0,120}\blocation\b[^\n.!?]{0,80}\bemail\b[^\n.!?]{0,80}\bbirthday\b/i
        $location_birthday_email = /\b(please|could you|can you)\b[^\n.!?]{0,48}\bupdate\s+my\b[^\n.!?]{0,80}\bprofile\b[^\n.!?]{0,120}\blocation\b[^\n.!?]{0,80}\bbirthday\b[^\n.!?]{0,80}\bemail\b/i
        $birthday_email_location = /\b(please|could you|can you)\b[^\n.!?]{0,48}\bupdate\s+my\b[^\n.!?]{0,80}\bprofile\b[^\n.!?]{0,120}\bbirthday\b[^\n.!?]{0,80}\bemail\b[^\n.!?]{0,80}\blocation\b/i
        $birthday_location_email = /\b(please|could you|can you)\b[^\n.!?]{0,48}\bupdate\s+my\b[^\n.!?]{0,80}\bprofile\b[^\n.!?]{0,120}\bbirthday\b[^\n.!?]{0,80}\blocation\b[^\n.!?]{0,80}\bemail\b/i
        $provider_profile_email_location_birthday = /(^|[\n.!?]\s*)(please\s+)?update\s+my\s+[A-Z][A-Z0-9_-]*\s+profile\s+email\s+to\s+["']?[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+["']?\s*,\s*location\b[^\n.!?]{0,80}\bbirthday\b/i
        $authorization_context = /\b(approved|approval|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        $email_location_birthday or $email_birthday_location or
        $location_email_birthday or $location_birthday_email or
        $birthday_email_location or $birthday_location_email or
        ($provider_profile_email_location_birthday and not $authorization_context)
}

rule defenseclaw_addressed_edit_access_grant {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a concrete request to grant edit access to an addressed principal"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "ACCESS CONTROL CHANGE"

    strings:
        $note_edit_grant = /(^|[\n.!?]\s*)please\s+change\s+the\s+sharing settings\b[^\n.!?]{0,160}\bfor\s+the\s+user\b[^\n.!?]{0,80}\bemail\b[^\n.!?]{0,24}["']?[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+[^\n.!?]{0,80}\b(can_edit|edit access)\b/i
        $note_edit_grant_reversed = /(^|[\n.!?]\s*)please\s+change\s+the\s+sharing settings\b[^\n.!?]{0,160}\b(can_edit|edit access)\b[^\n.!?]{0,80}\bfor\s+the\s+user\b[^\n.!?]{0,80}\bemail\b[^\n.!?]{0,24}["']?[A-Z0-9_%+-]+([.][A-Z0-9_%+-]+)*@[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $authorization_context = /\b(approved|approval|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        ($note_edit_grant or $note_edit_grant_reversed) and
        not $authorization_context
}

rule defenseclaw_sensitive_health_data_change {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a concrete genetic-data tamper or addressed application share"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "SENSITIVE HEALTH DATA CHANGE"

    strings:
        $genetic_risk_update = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?update\s+my\s+genetic data\b[^\n.!?]{0,120}\b(indicate|record|show)\b[^\n.!?]{0,80}\bhigh[- ]risk predisposition\b[^\n.!?]{0,120}\b(disease|diseases|condition|conditions|disorder|disorders)\b/i
        $genetic_app_share = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?share\s+my\s+genetic data\b[^\n]{0,160}\b(health([ -](monitoring|care))?|medical|third[- ]party)\s+(application|app)\b[^\n]{0,160}\b(application|app)[ _-]?id\b\s*(is\s*)?(:\s*)?["']?[A-Z0-9][A-Z0-9_-]{3,63}/i
        $authorization_context = /\b(approved|approval|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        ($genetic_risk_update or $genetic_app_share) and
        not $authorization_context
}

rule defenseclaw_traffic_control_override {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a bounded emergency-priority or individual traffic-light override"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "TRAFFIC CONTROL OVERRIDE"

    strings:
        $scheduled_emergency_priority = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?give\s+priority\s+to\s+an?\s+emergency vehicle\b[^\n]{0,160}\b(from\s+[0-9]{1,2}:[0-9]{2}\s*(am|pm)\s+to\s+[0-9]{1,2}:[0-9]{2}\s*(am|pm)|between\s+[0-9]{1,2}:[0-9]{2}\s*(am|pm)\s+and\s+[0-9]{1,2}:[0-9]{2}\s*(am|pm))\b[^\n]{0,120}\b(intersection|intersections)\b[^\n]{0,120}["']?[A-Z0-9][A-Z0-9_-]{1,31}["']?/i
        $bounded_light_state = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?change\s+the\s+state\s+of\s+the\s+traffic light\s+at\s+intersection\b[^\n.!?]{0,40}\b[A-Z]+[0-9][A-Z0-9_-]*\b[^\n.!?]{0,80}\b(light|signal)\b[^\n.!?]{0,80}\bto\s+["']?(red|green|yellow|amber)["']?\b[^\n.!?]{0,120}\b(starting\s+)?from\s+now\s+until\s+[0-9]{1,2}:[0-9]{2}\s*(am|pm)\b/i
        $authorization_context = /\b(approved|approval|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        ($scheduled_emergency_priority or $bounded_light_state) and
        not $authorization_context
}

rule defenseclaw_physical_access_change {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a concrete smart-lock guest grant or owned-door unlock request"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "PHYSICAL ACCESS CHANGE"

    strings:
        $permanent_smart_lock_guest = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?grant\s+permanent access\s+to\s+my\s+(friend|guest)\s+[A-Z][A-Z.-]{1,48}\s*\(\s*(guest[_-])?[A-Z0-9_-]{4,64}\s*\)\s+(on|in|to)\s+(the\s+)?[A-Z0-9 _-]{0,40}smart lock system\b/i
        $owned_door_unlock = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?unlock\s+my\s+(front|back|side|garage) door\b/i
        $authorization_context = /\b(approved|approval|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        ($permanent_smart_lock_guest or $owned_door_unlock) and
        not $authorization_context
}

rule defenseclaw_network_security_policy_change {
    meta:
        author = "Cisco DefenseClaw"
        description = "Detects a concrete allowlist or business-service denylist policy change"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"
        defenseclaw_category = "NETWORK SECURITY POLICY CHANGE"

    strings:
        $policy_allowlist_domains = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?update\s+my\s+security policy\b[^\n]{0,100}\bpolicy\s+id\b\s*[:=]?\s*["']?[A-Z0-9][A-Z0-9_-]{2,31}["']?[^\n]{0,180}\b(domains?\s+in\s+the\s+(whitelist|allowlist)|(whitelist|allowlist)\s+(the\s+)?(following\s+)?domains?)\b[^\n]{0,160}[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $business_service_denylist = /(^|[\n.!?]\s*)((please|could you|can you)\s+)?create\s+a\s+new\s+(blacklist|denylist) policy\b[^\n]{0,120}\bpolicy name\b\s*[:=]?\s*["']?[A-Z0-9][A-Z0-9 _-]{3,63}["']?[^\n]{0,180}\b(block|blocks|blocking|deny|denies|denying)\b[^\n]{0,120}\b(business services?|domains?)\b[^\n]{0,160}[A-Z0-9-]+([.][A-Z0-9-]+)+/i
        $authorization_context = /\b(approved|approval|authori(s|z)(e|ed|ation)|verified)\b/i

    condition:
        ($policy_allowlist_domains or $business_service_denylist) and
        not $authorization_context
}
