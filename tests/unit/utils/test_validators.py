"""Unit tests for validation utilities"""

import pytest
from pydantic import ValidationError

from project_argus.utils.validators import (
    DomainValidator,
    IPValidator,
    URLValidator,
    validate_domain,
    validate_ip,
    validate_url,
)


class TestURLValidator:
    """Test cases for URLValidator class"""

    def test_valid_url_with_scheme(self):
        """Test validation of URL with explicit scheme"""
        validator = URLValidator(url="https://example.com")
        assert validator.url == "https://example.com"

    def test_valid_url_without_scheme(self):
        """Test validation of URL without scheme (should add http://)"""
        validator = URLValidator(url="example.com")
        assert validator.url == "http://example.com"

    def test_empty_url_raises_error(self):
        """Test that empty URL raises ValueError"""
        with pytest.raises(ValidationError, match="URL cannot be empty"):
            URLValidator(url="")

    def test_localhost_url_raises_error(self):
        """Test that localhost URLs are rejected"""
        with pytest.raises(ValidationError):
            URLValidator(url="http://localhost")

    def test_private_ip_url_raises_error(self):
        """Test that private IP URLs are rejected"""
        with pytest.raises(
            ValidationError,
            match="URL cannot point to localhost or private IP address",
        ):
            URLValidator(url="http://192.168.1.1")

    def test_url_exceeds_max_length(self):
        """Test that overly long URLs are rejected"""
        long_url = "http://example.com/" + "a" * 2048
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            URLValidator(url=long_url)

    def test_url_with_invalid_scheme(self):
        """Test that invalid schemes are rejected"""
        with pytest.raises(ValidationError):
            URLValidator(url="javascript://alert(1)")

    def test_url_without_netloc(self):
        """Test that URLs without domain are rejected"""
        with pytest.raises(ValidationError, match="must contain a valid domain"):
            URLValidator(url="http://")

    def test_localhost_variant_rejected(self):
        """Test various localhost/loopback patterns are rejected"""
        localhost_urls = [
            "http://127.0.0.1",
            "http://127.1",
            "http://localhost:8080",
        ]
        for url in localhost_urls:
            with pytest.raises(ValidationError):
                URLValidator(url=url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/path",
            "http://subdomain.example.com",
            "https://example.com:8080",
            "http://example.com/path?query=value",
        ],
    )
    def test_valid_urls(self, url):
        """Test various valid URL formats"""
        validator = URLValidator(url=url)
        assert validator.url


class TestDomainValidator:
    """Test cases for DomainValidator class"""

    def test_valid_domain(self):
        """Test validation of valid domain"""
        validator = DomainValidator(domain="example.com")
        assert validator.domain == "example.com"

    def test_domain_with_protocol_stripped(self):
        """Test that protocol is stripped from domain"""
        validator = DomainValidator(domain="https://example.com")
        assert validator.domain == "example.com"

    def test_domain_with_path_stripped(self):
        """Test that path is stripped from domain"""
        validator = DomainValidator(domain="example.com/path/to/resource")
        assert validator.domain == "example.com"

    def test_domain_with_port_stripped(self):
        """Test that port is stripped from domain"""
        validator = DomainValidator(domain="example.com:8080")
        assert validator.domain == "example.com"

    def test_domain_with_query_stripped(self):
        """Test that query string is stripped from domain"""
        validator = DomainValidator(domain="example.com?query=value")
        assert validator.domain == "example.com"

    def test_ip_address_as_domain_raises_error(self):
        """Test that IP addresses are rejected as domains"""
        with pytest.raises(ValidationError, match="Expected domain name, got IP address"):
            DomainValidator(domain="192.168.1.1")

    def test_localhost_domain_raises_error(self):
        """Test that localhost is rejected"""
        with pytest.raises(ValidationError):
            DomainValidator(domain="localhost")

    def test_empty_domain_raises_error(self):
        """Test that empty domain raises error"""
        with pytest.raises(ValidationError, match="Domain cannot be empty"):
            DomainValidator(domain="")

    def test_domain_too_short(self):
        """Test that very short domains are rejected"""
        with pytest.raises(ValidationError):
            DomainValidator(domain="a.b")

    def test_domain_exceeds_max_length(self):
        """Test that overly long domains are rejected"""
        long_domain = "a" * 250 + ".com"
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            DomainValidator(domain=long_domain)

    def test_domain_with_null_byte(self):
        """Test that domains with null bytes are rejected"""
        with pytest.raises(ValidationError, match="null bytes"):
            DomainValidator(domain="example.com\x00malicious")

    def test_domain_single_label(self):
        """Test that single-label domains are rejected"""
        with pytest.raises(ValidationError, match="at least two labels"):
            DomainValidator(domain="singlelabel")

    def test_domain_label_starts_with_hyphen(self):
        """Test that labels starting with hyphen are rejected"""
        with pytest.raises(ValidationError, match="cannot start or end with hyphen"):
            DomainValidator(domain="-invalid.com")

    def test_domain_label_ends_with_hyphen(self):
        """Test that labels ending with hyphen are rejected"""
        with pytest.raises(ValidationError, match="cannot start or end with hyphen"):
            DomainValidator(domain="invalid-.com")

    def test_domain_label_exceeds_max_length(self):
        """Test that labels exceeding 63 chars are rejected"""
        long_label = "a" * 64
        with pytest.raises(ValidationError, match="label exceeds maximum length"):
            DomainValidator(domain=f"{long_label}.com")

    def test_invalid_tld_format(self):
        """Test that invalid TLD formats are rejected"""
        with pytest.raises(ValidationError, match="Invalid TLD format"):
            DomainValidator(domain="example.c")

    @pytest.mark.parametrize(
        "domain",
        [
            "domain.local",
            "test.internal",
            "server.corp",
            "home.lan",
            "example.test",
        ],
    )
    def test_suspicious_domains_rejected(self, domain):
        """Test that suspicious TLDs are rejected"""
        with pytest.raises(ValidationError, match="internal or suspicious TLD"):
            DomainValidator(domain=domain)

    @pytest.mark.parametrize(
        "domain",
        [
            "example.com",
            "subdomain.example.com",
            "my-domain.co.uk",
            "test123.example.org",
        ],
    )
    def test_valid_domains(self, domain):
        """Test various valid domain formats"""
        validator = DomainValidator(domain=domain)
        assert validator.domain == domain.lower()


class TestIPValidator:
    """Test cases for IPValidator class"""

    def test_valid_ipv4(self):
        """Test validation of valid IPv4 address"""
        validator = IPValidator(ip="8.8.8.8")
        assert validator.ip == "8.8.8.8"

    def test_valid_ipv6(self):
        """Test validation of valid IPv6 address"""
        validator = IPValidator(ip="2001:4860:4860::8888")
        assert validator.ip == "2001:4860:4860::8888"

    def test_ipv6_with_brackets(self):
        """Test IPv6 address with brackets stripped"""
        validator = IPValidator(ip="[2001:4860:4860::8888]")
        assert validator.ip == "2001:4860:4860::8888"

    def test_empty_ip_raises_error(self):
        """Test that empty IP raises error"""
        with pytest.raises(ValidationError, match="IP address cannot be empty"):
            IPValidator(ip="")

    def test_private_ip_raises_error(self):
        """Test that private IPs are rejected"""
        with pytest.raises(ValidationError, match="Private IP"):
            IPValidator(ip="192.168.1.1")

    def test_loopback_ip_raises_error(self):
        """Test that loopback IPs are rejected"""
        with pytest.raises(ValidationError, match="Loopback"):
            IPValidator(ip="127.0.0.1")

    def test_link_local_ip_raises_error(self):
        """Test that link-local IPs are rejected"""
        with pytest.raises(ValidationError, match="Link-local"):
            IPValidator(ip="169.254.1.1")

    def test_multicast_ip_raises_error(self):
        """Test that multicast IPs are rejected"""
        with pytest.raises(ValidationError, match="Multicast"):
            IPValidator(ip="224.0.0.1")

    def test_unspecified_ip_raises_error(self):
        """Test that unspecified IPs are rejected"""
        with pytest.raises(ValidationError, match="Unspecified"):
            IPValidator(ip="0.0.0.0")

    def test_reserved_ip_raises_error(self):
        """Test that reserved IPs are rejected"""
        with pytest.raises(ValidationError, match="Reserved"):
            IPValidator(ip="240.0.0.1")

    def test_null_byte_in_ip(self):
        """Test that IPs with null bytes are rejected"""
        with pytest.raises(ValidationError, match="null bytes"):
            IPValidator(ip="8.8.8.8\x00")

    def test_invalid_ip_format_raises_error(self):
        """Test that invalid IP format raises error"""
        with pytest.raises(ValidationError, match="Invalid IP"):
            IPValidator(ip="999.999.999.999")

    def test_ipv4_mapped_ipv6_rejected(self):
        """Test that IPv4-mapped IPv6 addresses are rejected"""
        with pytest.raises(ValidationError, match="IPv4-mapped"):
            IPValidator(ip="::ffff:192.168.1.1")

    def test_ipv6_loopback_rejected(self):
        """Test that IPv6 loopback is rejected"""
        with pytest.raises(ValidationError, match="Loopback"):
            IPValidator(ip="::1")

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
        ],
    )
    def test_private_ipv4_addresses(self, ip):
        """Test various private IPv4 addresses are rejected"""
        with pytest.raises(ValidationError, match="Private IP"):
            IPValidator(ip=ip)

    @pytest.mark.parametrize(
        "ip",
        [
            "1.1.1.1",
            "8.8.4.4",
            "208.67.222.222",
            "2606:4700:4700::1111",
            "2001:4860:4860::8844",
        ],
    )
    def test_valid_public_ips(self, ip):
        """Test various valid public IP addresses"""
        validator = IPValidator(ip=ip)
        assert validator.ip


class TestURLValidatorIsValidHostname:
    """Additional tests targeting URLValidator._is_valid_hostname edge cases."""

    def test_hostname_too_long_returns_false(self):
        assert URLValidator._is_valid_hostname("a" * 254) is False

    def test_empty_hostname_returns_false(self):
        assert URLValidator._is_valid_hostname("") is False

    def test_single_label_hostname_returns_false(self):
        assert URLValidator._is_valid_hostname("singlelabel") is False

    def test_label_too_long_returns_false(self):
        long_label = "a" * 64
        assert URLValidator._is_valid_hostname(f"{long_label}.com") is False

    def test_empty_label_in_hostname_returns_false(self):
        # double dot creates an empty label
        assert URLValidator._is_valid_hostname("example..com") is False

    def test_tld_with_digit_returns_false(self):
        assert URLValidator._is_valid_hostname("example.c0m") is False

    def test_valid_hostname_returns_true(self):
        assert URLValidator._is_valid_hostname("example.com") is True

    def test_idn_hostname_decoded(self):
        # IDNA-encoded label — decode should succeed
        result = URLValidator._is_valid_hostname("xn--nxasmq6b.com")
        # Either True or False is acceptable; the important thing is no exception
        assert isinstance(result, bool)


class TestURLValidatorIsSuspiciousHost:
    """Additional tests for URLValidator._is_suspicious_host."""

    def test_localhost_is_suspicious(self):
        assert URLValidator._is_suspicious_host("localhost") is True

    def test_127_prefix_is_suspicious(self):
        assert URLValidator._is_suspicious_host("127.0.0.1") is True

    def test_zero_address_is_suspicious(self):
        assert URLValidator._is_suspicious_host("0.0.0.0") is True

    def test_ipv6_loopback_is_suspicious(self):
        assert URLValidator._is_suspicious_host("::1") is True

    def test_private_ipv4_is_suspicious(self):
        assert URLValidator._is_suspicious_host("192.168.1.1") is True

    def test_private_10_prefix_is_suspicious(self):
        assert URLValidator._is_suspicious_host("10.0.0.1") is True

    def test_public_ip_is_not_suspicious(self):
        assert URLValidator._is_suspicious_host("8.8.8.8") is False

    def test_regular_domain_is_not_suspicious(self):
        assert URLValidator._is_suspicious_host("example.com") is False


class TestURLValidatorSuspiciousURLPatterns:
    """Test URLs that hit the SSRF/suspicious-host check path in validate_url."""

    def test_0_0_0_0_rejected(self):
        with pytest.raises(ValidationError):
            URLValidator(url="http://0.0.0.0")

    def test_ftp_url_rejected_as_no_scheme(self):
        """ftp:// is added http:// prefix and then rejected for bad hostname."""
        with pytest.raises(ValidationError):
            URLValidator(url="ftp://example.com")


class TestDomainValidatorEdgeCases:
    """Additional coverage for DomainValidator."""

    def test_ftp_protocol_stripped(self):
        validator = DomainValidator(domain="ftp://example.com")
        assert validator.domain == "example.com"

    def test_domain_with_fragment_stripped(self):
        validator = DomainValidator(domain="example.com#section")
        assert validator.domain == "example.com"

    def test_domain_with_ipv6_brackets_stripped(self):
        """IPv6 bracketed addresses are stripped, then rejected as IP."""
        with pytest.raises(ValidationError):
            DomainValidator(domain="[::1]")

    def test_domain_with_invalid_chars_in_label(self):
        with pytest.raises(ValidationError):
            DomainValidator(domain="exam!ple.com")

    def test_empty_label_rejected(self):
        with pytest.raises(ValidationError, match="empty label"):
            DomainValidator(domain="example..com")

    def test_numeric_only_tld_rejected(self):
        with pytest.raises(ValidationError, match="Invalid TLD"):
            DomainValidator(domain="example.123")

    def test_suspicious_domain_localhost(self):
        from project_argus.utils.validators import DomainValidator as DV

        assert DV._is_suspicious_domain("localhost") is True

    def test_suspicious_domain_example_tld(self):
        from project_argus.utils.validators import DomainValidator as DV

        assert DV._is_suspicious_domain("something.example") is True

    def test_non_suspicious_domain(self):
        from project_argus.utils.validators import DomainValidator as DV

        assert DV._is_suspicious_domain("example.com") is False


class TestStandaloneFunctions:
    """Tests for the module-level validate_url, validate_domain, validate_ip helpers."""

    def test_validate_url_valid(self):
        result = validate_url("https://example.com")
        assert result == "https://example.com"

    def test_validate_url_invalid_raises(self):
        with pytest.raises(ValueError):
            validate_url("http://localhost")

    def test_validate_domain_valid(self):
        result = validate_domain("example.com")
        assert result == "example.com"

    def test_validate_domain_invalid_raises(self):
        with pytest.raises(ValueError):
            validate_domain("localhost")

    def test_validate_ip_valid(self):
        result = validate_ip("8.8.8.8")
        assert result == "8.8.8.8"

    def test_validate_ip_invalid_raises(self):
        with pytest.raises(ValueError):
            validate_ip("127.0.0.1")
