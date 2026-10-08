"""The Okta installer preserves other SSSD domains."""
import pathlib
import subprocess

KIT = pathlib.Path(__file__).parent

def test_repeat_install_keeps_other_sssd_domain(tmp_path):
    existing = tmp_path / "sssd.conf"
    rendered = tmp_path / "rendered.conf"
    content = "# Managed by DefenseClaw packaging/identity/okta/install-sssd-okta.sh.\n" \
              "[sssd]\ndomains = okta, ad\n[domain/okta]\nid_provider = ldap\n" \
              "[domain/ad]\nid_provider = ad\n"
    existing.write_text(content)
    rendered.write_text(content.replace("okta, ad", "okta").replace("[domain/ad]\nid_provider = ad\n", ""))
    script = f"""source {KIT / 'install-sssd-okta.sh'}
CONF={existing}
DOMAIN=okta
FORCE=0
DRY_RUN=0
install_conf {rendered}
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert result.returncode == 3
    assert existing.read_text() == content
