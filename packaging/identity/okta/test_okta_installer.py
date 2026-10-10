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
    source = (KIT / "install-sssd-okta.sh").read_text().rsplit('main "$@"', 1)[0]
    script = source + f"""
CONF={existing}
DOMAIN=okta
FORCE=0
DRY_RUN=0
install_conf {rendered}
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert result.returncode == 3
    assert existing.read_text() == content


def test_local_allow_group_is_rejected_before_sshd_changes(tmp_path):
    source = (KIT / "install-sssd-okta.sh").read_text().rsplit('main "$@"', 1)[0]
    script = source + """
fetch_password() { PASSWORD=stub; }
check_host() { :; }
render() { :; }
config_check() { :; }
bind_test() { :; }
authselect_profile_check() { :; }
install_conf() { :; }
pam_step() { :; }
sshd_step() { echo "unexpected sshd step"; }
restart_sssd() { :; }
main --org example --bind-login bind@example.com --allow-group root --dry-run
"""
    test_script = tmp_path / "installer.sh"
    test_script.write_text(script)
    result = subprocess.run(["bash", str(test_script)], capture_output=True, text=True)
    assert result.returncode == 3
    assert "local group" in result.stderr
    assert "unexpected sshd step" not in result.stdout


def test_unchanged_dry_run_without_password_does_not_plan_sssd_replacement(tmp_path):
    source = (KIT / "install-sssd-okta.sh").read_text().rsplit('main "$@"', 1)[0]
    existing = tmp_path / "sssd.conf"
    existing.write_text("# Managed by DefenseClaw packaging/identity/okta/install-sssd-okta.sh.\n")
    script = source + f"""
CONF={existing}
check_local_allow_group() {{ :; }}
check_host() {{ :; }}
render() {{ echo 'unexpected render'; return 1; }}
bind_test() {{ echo 'unexpected bind test'; return 1; }}
install_conf() {{ echo 'unexpected config replacement'; return 1; }}
authselect_profile_check() {{ :; }}
pam_step() {{ :; }}
sshd_step() {{ :; }}
systemctl() {{ [[ $1 == is-enabled ]]; }}
main --org example --bind-login bind@example.com --allow-group linux-users --dry-run
"""
    test_script = tmp_path / "installer.sh"
    test_script.write_text(script)
    result = subprocess.run(["bash", str(test_script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "cannot judge SSSD config without the bind password" in result.stdout
    assert "would replace" not in result.stdout
    assert "would restart" not in result.stdout
    assert "unexpected" not in result.stdout
    assert "changed: 0" in result.stdout
