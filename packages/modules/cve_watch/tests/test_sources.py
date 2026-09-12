from seclab_cve_watch.sources import (
    merge_cves,
    mock_cisa_kev,
    mock_nvd_cves,
    parse_cisa_kev_response,
    parse_nvd_response,
)

SAMPLE_NVD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2099-0001",
                "published": "2099-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "A test remote code execution flaw."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.1}},
                    ]
                },
            }
        }
    ]
}

SAMPLE_KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2099-0001",
            "vendorProject": "TestVendor",
            "product": "TestProduct",
            "dateAdded": "2099-01-02",
            "shortDescription": "Actively exploited test flaw.",
        }
    ]
}


def test_parse_nvd_response_extracts_cves():
    cves = parse_nvd_response(SAMPLE_NVD)
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2099-0001"
    assert cves[0].cvss_score == 9.1
    assert cves[0].source == "NVD"
    assert cves[0].is_actively_exploited is False


def test_parse_cisa_kev_response_extracts_cves():
    cves = parse_cisa_kev_response(SAMPLE_KEV)
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2099-0001"
    assert cves[0].is_actively_exploited is True
    assert cves[0].source == "CISA KEV"


def test_merge_cves_combines_nvd_and_kev_by_cve_id():
    nvd_cves = parse_nvd_response(SAMPLE_NVD)
    kev_cves = parse_cisa_kev_response(SAMPLE_KEV)

    merged = merge_cves(nvd_cves, kev_cves)

    assert len(merged) == 1
    combined = merged[0]
    assert combined.cve_id == "CVE-2099-0001"
    assert combined.is_actively_exploited is True
    assert combined.cvss_score == 9.1
    assert combined.source == "NVD + CISA KEV"


def test_merge_cves_keeps_kev_only_entries():
    merged = merge_cves([], parse_cisa_kev_response(SAMPLE_KEV))
    assert len(merged) == 1
    assert merged[0].is_actively_exploited is True
    assert merged[0].source == "CISA KEV"


def test_mock_nvd_cves_returns_offline_fixture_data():
    cves = parse_nvd_response(mock_nvd_cves())
    assert len(cves) == 4
    assert all(cve.cve_id.startswith("CVE-") for cve in cves)


def test_mock_cisa_kev_returns_offline_fixture_data():
    cves = parse_cisa_kev_response(mock_cisa_kev())
    assert len(cves) == 3
    assert all(cve.is_actively_exploited for cve in cves)
