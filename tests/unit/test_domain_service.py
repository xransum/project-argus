"""Unit tests for DomainService"""

import socket
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from project_argus.services.domain_service import DomainService


@pytest.fixture
def domain_service():
    """Create a DomainService instance"""
    return DomainService()


@pytest.fixture
def sample_domain():
    """Sample domain for testing"""
    return "example.com"


class TestDomainInfo:
    """Tests for get_domain_info"""

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.whois.whois")
    async def test_get_domain_info_success(self, mock_whois, domain_service, sample_domain):
        """Test successful domain info retrieval"""
        mock_whois_result = Mock()
        mock_whois_result.registrar = "Example Registrar"
        mock_whois_result.creation_date = datetime(2000, 1, 1)
        mock_whois_result.expiration_date = datetime(2025, 1, 1)
        mock_whois_result.name_servers = ["ns1.example.com", "ns2.example.com"]
        mock_whois.return_value = mock_whois_result

        result = await domain_service.get_domain_info(sample_domain)

        assert result.domain == sample_domain
        assert result.registrar == "Example Registrar"
        assert result.creation_date == datetime(2000, 1, 1)
        assert result.expiration_date == datetime(2025, 1, 1)
        assert result.name_servers == ["ns1.example.com", "ns2.example.com"]

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.whois.whois")
    async def test_get_domain_info_no_attributes(self, mock_whois, domain_service, sample_domain):
        """Test domain info with missing attributes"""
        mock_whois_result = Mock(spec=[])  # No attributes
        mock_whois.return_value = mock_whois_result

        result = await domain_service.get_domain_info(sample_domain)

        assert result.domain == sample_domain
        assert result.registrar is None
        assert result.creation_date is None
        assert result.expiration_date is None
        assert result.name_servers == []

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.whois.whois")
    async def test_get_domain_info_exception(self, mock_whois, domain_service, sample_domain):
        """Test domain info when exception occurs"""
        mock_whois.side_effect = Exception("WHOIS error")

        result = await domain_service.get_domain_info(sample_domain)

        assert result.domain == sample_domain
        assert result.name_servers == []


class TestSSLCheck:
    """Tests for check_ssl"""

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.create_connection")
    @patch("project_argus.services.domain_service.ssl.create_default_context")
    async def test_check_ssl_success(
        self, mock_ssl_context, mock_socket, domain_service, sample_domain
    ):
        """Test successful SSL check"""
        # Mock certificate
        future_date = datetime.now() + timedelta(days=90)
        cert = {
            "notAfter": future_date.strftime("%b %d %H:%M:%S %Y GMT"),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
        }

        # Mock SSL socket
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = cert
        mock_ssl_socket.__enter__ = Mock(return_value=mock_ssl_socket)
        mock_ssl_socket.__exit__ = Mock(return_value=False)

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.__enter__ = Mock(return_value=mock_connection)
        mock_connection.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_connection

        # Mock context
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context

        result = await domain_service.check_ssl(sample_domain)

        assert result.domain == sample_domain
        assert result.has_ssl is True
        assert result.valid is True
        assert result.issuer == "Let's Encrypt"
        assert result.days_until_expiry >= 89

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.create_connection")
    @patch("project_argus.services.domain_service.ssl.create_default_context")
    async def test_check_ssl_no_cert(
        self, mock_ssl_context, mock_socket, domain_service, sample_domain
    ):
        """Test SSL check with no certificate"""
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = None
        mock_ssl_socket.__enter__ = Mock(return_value=mock_ssl_socket)
        mock_ssl_socket.__exit__ = Mock(return_value=False)

        mock_connection = MagicMock()
        mock_connection.__enter__ = Mock(return_value=mock_connection)
        mock_connection.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_connection

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context

        result = await domain_service.check_ssl(sample_domain)

        assert result.domain == sample_domain
        assert result.has_ssl is False
        assert result.valid is False

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.create_connection")
    @patch("project_argus.services.domain_service.ssl.create_default_context")
    async def test_check_ssl_expired(
        self, mock_ssl_context, mock_socket, domain_service, sample_domain
    ):
        """Test SSL check with expired certificate"""
        past_date = datetime.now() - timedelta(days=30)
        cert = {
            "notAfter": past_date.strftime("%b %d %H:%M:%S %Y GMT"),
            "issuer": ((("organizationName", "Test CA"),),),
        }

        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = cert
        mock_ssl_socket.__enter__ = Mock(return_value=mock_ssl_socket)
        mock_ssl_socket.__exit__ = Mock(return_value=False)

        mock_connection = MagicMock()
        mock_connection.__enter__ = Mock(return_value=mock_connection)
        mock_connection.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_connection

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context

        result = await domain_service.check_ssl(sample_domain)

        assert result.domain == sample_domain
        assert result.has_ssl is True
        assert result.valid is False

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.create_connection")
    async def test_check_ssl_exception(self, mock_socket, domain_service, sample_domain):
        """Test SSL check when exception occurs"""
        mock_socket.side_effect = Exception("Connection error")

        result = await domain_service.check_ssl(sample_domain)

        assert result.domain == sample_domain
        assert result.has_ssl is False
        assert result.valid is False

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.create_connection")
    @patch("project_argus.services.domain_service.ssl.create_default_context")
    async def test_check_ssl_no_expiry(
        self, mock_ssl_context, mock_socket, domain_service, sample_domain
    ):
        """Test SSL check with no expiry date"""
        cert = {
            "notAfter": "",
            "issuer": ((("organizationName", "Test CA"),),),
        }

        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = cert
        mock_ssl_socket.__enter__ = Mock(return_value=mock_ssl_socket)
        mock_ssl_socket.__exit__ = Mock(return_value=False)

        mock_connection = MagicMock()
        mock_connection.__enter__ = Mock(return_value=mock_connection)
        mock_connection.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_connection

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context

        result = await domain_service.check_ssl(sample_domain)

        assert result.domain == sample_domain
        assert result.has_ssl is True
        assert result.valid is False


class TestDNSRecords:
    """Tests for get_dns_records"""

    @pytest.mark.asyncio
    async def test_get_dns_records_success(self, domain_service, sample_domain):
        """Test successful DNS record retrieval"""
        mock_answer = ["93.184.216.34"]
        domain_service.resolver.resolve = Mock(return_value=mock_answer)

        result = await domain_service.get_dns_records(sample_domain, "A")

        assert result.domain == sample_domain
        assert result.record_type == "A"
        assert result.records == ["93.184.216.34"]

    @pytest.mark.asyncio
    async def test_get_dns_records_exception(self, domain_service, sample_domain):
        """Test DNS records when exception occurs"""
        domain_service.resolver.resolve = Mock(side_effect=Exception("DNS error"))

        result = await domain_service.get_dns_records(sample_domain, "A")

        assert result.domain == sample_domain
        assert result.record_type == "A"
        assert result.records == []


class TestWHOIS:
    """Tests for get_whois"""

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.whois.whois")
    async def test_get_whois_success(self, mock_whois, domain_service, sample_domain):
        """Test successful WHOIS retrieval"""
        mock_whois_result = Mock()
        mock_whois_result.registrar = "Test Registrar"
        mock_whois_result.creation_date = datetime(2000, 1, 1)
        mock_whois_result.expiration_date = datetime(2025, 1, 1)
        mock_whois_result.updated_date = datetime(2024, 1, 1)
        mock_whois_result.name_servers = ["ns1.example.com"]
        mock_whois_result.status = ["clientTransferProhibited"]
        mock_whois.return_value = mock_whois_result

        result = await domain_service.get_whois(sample_domain)

        assert result.domain == sample_domain
        assert result.registrar == "Test Registrar"
        assert result.creation_date == datetime(2000, 1, 1)
        assert result.status == ["clientTransferProhibited"]

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.whois.whois")
    async def test_get_whois_exception(self, mock_whois, domain_service, sample_domain):
        """Test WHOIS when exception occurs"""
        mock_whois.side_effect = Exception("WHOIS error")

        result = await domain_service.get_whois(sample_domain)

        assert result.domain == sample_domain


class TestGeoIP:
    """Tests for get_geoip"""

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.gethostbyname")
    async def test_get_geoip_success(self, mock_gethostbyname, domain_service, sample_domain):
        """Test successful GeoIP retrieval"""
        mock_gethostbyname.return_value = "93.184.216.34"

        result = await domain_service.get_geoip(sample_domain)

        assert result.domain == sample_domain
        assert result.ip == "93.184.216.34"
        assert result.country == "Unknown"
        assert result.city == "Unknown"

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.gethostbyname")
    async def test_get_geoip_exception(self, mock_gethostbyname, domain_service, sample_domain):
        """Test GeoIP when exception occurs"""
        mock_gethostbyname.side_effect = Exception("DNS error")

        result = await domain_service.get_geoip(sample_domain)

        assert result.domain == sample_domain
        assert result.ip == ""


class TestReputation:
    """Tests for check_reputation"""

    @pytest.mark.asyncio
    async def test_check_reputation(self, domain_service, sample_domain):
        """Test reputation check"""
        result = await domain_service.check_reputation(sample_domain)

        assert result.domain == sample_domain
        assert result.score == 75
        assert result.is_safe is True
        assert result.categories == []


class TestBlacklist:
    """Tests for check_blacklist"""

    @pytest.mark.asyncio
    async def test_check_blacklist(self, domain_service, sample_domain):
        """Test blacklist check"""
        result = await domain_service.check_blacklist(sample_domain)

        assert result.domain == sample_domain
        assert result.is_blacklisted is False
        assert result.blacklists == []


class TestSSLCertificate:
    """Tests for get_ssl_certificate"""

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.create_connection")
    @patch("project_argus.services.domain_service.ssl.create_default_context")
    async def test_get_ssl_certificate_success(
        self, mock_ssl_context, mock_socket, domain_service, sample_domain
    ):
        """Test successful SSL certificate retrieval"""
        # Create a test certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
                x509.NameAttribute(NameOID.COMMON_NAME, sample_domain),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        der_cert = cert.public_bytes(encoding=serialization.Encoding.DER)

        mock_ssl_socket = MagicMock()
        mock_ssl_socket.__enter__ = Mock(return_value=mock_ssl_socket)
        mock_ssl_socket.__exit__ = Mock(return_value=False)

        # Mock to return DER certificate
        def mock_getpeercert(binary_form=False):
            if binary_form:
                return der_cert
            return {"notAfter": "Dec 31 23:59:59 2025 GMT"}

        mock_ssl_socket.getpeercert = mock_getpeercert

        mock_connection = MagicMock()
        mock_connection.__enter__ = Mock(return_value=mock_connection)
        mock_connection.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_connection

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context

        result = await domain_service.get_ssl_certificate(sample_domain)

        assert result.domain == sample_domain
        assert result.public_key_size == 2048
        assert "commonName" in result.subject

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.create_connection")
    @patch("project_argus.services.domain_service.ssl.create_default_context")
    async def test_get_ssl_certificate_no_cert(
        self, mock_ssl_context, mock_socket, domain_service, sample_domain
    ):
        """Test SSL certificate retrieval with no certificate"""
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = None
        mock_ssl_socket.__enter__ = Mock(return_value=mock_ssl_socket)
        mock_ssl_socket.__exit__ = Mock(return_value=False)

        mock_connection = MagicMock()
        mock_connection.__enter__ = Mock(return_value=mock_connection)
        mock_connection.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_connection

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context

        with pytest.raises(Exception, match="No certificate found"):
            await domain_service.get_ssl_certificate(sample_domain)

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.create_connection")
    async def test_get_ssl_certificate_exception(self, mock_socket, domain_service, sample_domain):
        """Test SSL certificate retrieval when exception occurs"""
        mock_socket.side_effect = Exception("Connection error")

        with pytest.raises(Exception, match="Failed to fetch SSL certificate"):
            await domain_service.get_ssl_certificate(sample_domain)


class TestSubdomains:
    """Tests for get_subdomains"""

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.gethostbyname")
    async def test_get_subdomains_success(self, mock_gethostbyname, domain_service, sample_domain):
        """Test successful subdomain discovery"""

        # Mock successful resolution for www and mail
        def mock_resolve(subdomain):
            if subdomain in ["www.example.com", "mail.example.com"]:
                return "93.184.216.34"
            raise socket.gaierror("Name or service not known")

        mock_gethostbyname.side_effect = mock_resolve

        result = await domain_service.get_subdomains(sample_domain)

        assert result.domain == sample_domain
        assert "www.example.com" in result.subdomains
        assert "mail.example.com" in result.subdomains

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.gethostbyname")
    async def test_get_subdomains_none_found(
        self, mock_gethostbyname, domain_service, sample_domain
    ):
        """Test subdomain discovery when none found"""
        mock_gethostbyname.side_effect = Exception("DNS error")

        result = await domain_service.get_subdomains(sample_domain)

        assert result.domain == sample_domain
        assert result.subdomains == []


class TestHostingInfo:
    """Tests for get_hosting_info"""

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.gethostbyname")
    async def test_get_hosting_info_success(
        self, mock_gethostbyname, domain_service, sample_domain
    ):
        """Test successful hosting info retrieval"""
        mock_gethostbyname.return_value = "93.184.216.34"

        result = await domain_service.get_hosting_info(sample_domain)

        assert result.domain == sample_domain
        assert result.ip_address == "93.184.216.34"
        assert result.hosting_provider == "Unknown"
        assert result.asn == "Unknown"
        assert result.organization == "Unknown"

    @pytest.mark.asyncio
    @patch("project_argus.services.domain_service.socket.gethostbyname")
    async def test_get_hosting_info_exception(
        self, mock_gethostbyname, domain_service, sample_domain
    ):
        """Test hosting info when exception occurs"""
        mock_gethostbyname.side_effect = Exception("DNS error")

        result = await domain_service.get_hosting_info(sample_domain)

        assert result.domain == sample_domain
        assert result.ip_address == ""


class TestParseDateHelper:
    """Tests for _parse_date helper method"""

    def test_parse_date_list(self, domain_service):
        """Test parsing date from list"""
        date = datetime(2000, 1, 1)
        result = domain_service._parse_date([date])
        assert result == date

    def test_parse_date_empty_list(self, domain_service):
        """Test parsing date from empty list"""
        result = domain_service._parse_date([])
        assert result is None

    def test_parse_date_datetime(self, domain_service):
        """Test parsing date from datetime"""
        date = datetime(2000, 1, 1)
        result = domain_service._parse_date(date)
        assert result == date

    def test_parse_date_other(self, domain_service):
        """Test parsing date from other types"""
        result = domain_service._parse_date("2000-01-01")
        assert result is None

    def test_parse_date_none(self, domain_service):
        """Test parsing None"""
        result = domain_service._parse_date(None)
        assert result is None
