from seclab_phantom.models import DomainVariation, TargetProfile, TargetRequest, TargetType

COMMON_TLDS = ("com", "net", "org", "co", "io", "biz")
HOMOGLYPHS = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}
LURE_TERMS = ("login", "secure", "verify", "portal")


def build_target_profile(request: TargetRequest) -> TargetProfile:
    normalized = request.target.strip().lower()
    if request.target_type == TargetType.DOMAIN:
        parts = normalized.split(".")
        brand_keyword = parts[0]
        root_domain = normalized
        apex_domain = ".".join(parts[-2:]) if len(parts) >= 2 else normalized
    else:
        brand_keyword = normalized.replace(" ", "")
        root_domain = None
        apex_domain = None
    return TargetProfile(
        original_input=request.target,
        normalized_target=normalized,
        brand_keyword=brand_keyword,
        root_domain=root_domain,
        apex_domain=apex_domain,
    )


def generate_domain_variants(profile: TargetProfile, limit: int = 10) -> list[DomainVariation]:
    keyword = profile.brand_keyword
    variants: list[DomainVariation] = []

    def add(candidate: str, technique: str, *tags: str) -> None:
        if len(variants) >= limit or "." not in candidate:
            return
        if candidate == profile.root_domain:
            return
        if not any(item.domain == candidate for item in variants):
            variants.append(
                DomainVariation(
                    domain=candidate,
                    technique=technique,
                    source_target=profile.normalized_target,
                    risk_context_tags=list(tags),
                )
            )

    for tld in COMMON_TLDS:
        for lure in LURE_TERMS:
            add(f"{lure}-{keyword}.{tld}", "brand-prefix", "credential-lure")
        add(f"{keyword}-support.{tld}", "support-lure", "support-theme")
        add(f"{keyword}-secure.{tld}", "security-lure", "credential-lure")
        add(f"{keyword}{tld}.{tld}", "tld-blend", "brand-concatenation")

    if len(keyword) > 3:
        add(f"{keyword[:-1]}.{COMMON_TLDS[0]}", "character-omission", "typing-error")
        add(f"{keyword}{keyword[-1]}.{COMMON_TLDS[0]}", "character-duplication", "typing-error")
        add(f"{keyword[:-1]}0.{COMMON_TLDS[0]}", "character-swap", "homoglyph-risk")

    for original, replacement in HOMOGLYPHS.items():
        if original in keyword and len(variants) < limit:
            add(
                f"{keyword.replace(original, replacement, 1)}.{COMMON_TLDS[0]}",
                "homoglyph",
                "homoglyph-risk",
            )

    return variants[:limit]
