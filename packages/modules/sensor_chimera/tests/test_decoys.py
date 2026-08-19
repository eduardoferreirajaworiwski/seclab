from seclab_sensor_chimera.decoys import aws_credentials_decoy, dotenv_decoy, git_config_decoy


def test_aws_decoy_has_expected_shape():
    decoy = aws_credentials_decoy()
    assert decoy["Type"] == "AWS-HMAC"
    assert decoy["AccessKeyId"].startswith("ASIA")
    assert decoy["SecretAccessKey"]


def test_dotenv_decoy_contains_fake_markers():
    decoy = dotenv_decoy()
    assert "DB_HOST" in decoy
    assert "STRIPE_LIVE_KEY" in decoy


def test_git_config_decoy_is_well_formed():
    decoy = git_config_decoy()
    assert '[remote "origin"]' in decoy
    assert "url = " in decoy
