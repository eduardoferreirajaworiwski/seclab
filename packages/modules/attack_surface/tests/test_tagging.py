from seclab_attack_surface.tagging import EXPOSURE_TAGS, tag_open_ports


def test_rdp_port_maps_to_rdp_exposed_tag():
    tags = tag_open_ports([3389])
    assert tags == ["rdp-exposed"]


def test_ftp_port_maps_to_ftp_exposed_tag():
    tags = tag_open_ports([21])
    assert tags == ["ftp-exposed"]


def test_web_ports_alone_produce_no_exposure_tags():
    tags = tag_open_ports([80, 443])
    assert tags == []


def test_multiple_sensitive_ports_produce_multiple_tags_in_deterministic_order():
    tags = tag_open_ports([443, 3389, 80, 21])
    # order follows EXPOSURE_TAGS definition order, not the input order
    assert tags == ["ftp-exposed", "rdp-exposed"]


def test_empty_port_list_produces_no_tags():
    assert tag_open_ports([]) == []


def test_exposure_tags_mapping_is_named_and_explainable():
    assert EXPOSURE_TAGS[21] == "ftp-exposed"
    assert EXPOSURE_TAGS[3389] == "rdp-exposed"
