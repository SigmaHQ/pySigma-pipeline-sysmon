from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.pipelines.sysmon import sysmon_pipeline
import pytest


@pytest.fixture
def process_creation_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image: "*\\\\test.exe"
            condition: sel
    """
    )


@pytest.fixture
def file_change_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: File Change Test
        status: test
        logsource:
            category: file_change
            product: windows
        detection:
            sel:
                TargetFilename: test
            condition: sel
    """
    )


@pytest.fixture
def network_connection_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Network Connection Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
               Initiated: "true"
               DestinationIp: "1.2.3.4"
            condition: sel
    """
    )


@pytest.fixture
def process_termination_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Process Termination Test
        status: test
        logsource:
            category: process_termination
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def driver_load_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Driver Load Test
        status: test
        logsource:
            category: driver_load
            product: windows
        detection:
            sel:
                ImageLoaded: test.exe
            condition: sel
    """
    )


@pytest.fixture
def image_load_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Image Load Test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                ImageLoaded: test.exe
            condition: sel
    """
    )


@pytest.fixture
def create_remote_thread_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Create Remote Thread Test
        status: test
        logsource:
            category: create_remote_thread
            product: windows
        detection:
            sel:
                SourceImage: test.exe
            condition: sel
    """
    )


@pytest.fixture
def raw_access_thread_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Raw Access Thread Test
        status: test
        logsource:
            category: raw_access_thread
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def process_access_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Process Access Test
        status: test
        logsource:
            category: process_access
            product: windows
        detection:
            sel:
                TargetImage: test.exe
            condition: sel
    """
    )


@pytest.fixture
def file_event_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: File Event Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel:
                TargetFilename: test.exe
            condition: sel
    """
    )


@pytest.fixture
def registry_event_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Registry Event Test
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def registry_add_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Registry Add Test
        status: test
        logsource:
            category: registry_add
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def registry_delete_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Registry Delete Test
        status: test
        logsource:
            category: registry_delete
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def registry_set_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Registry Set Test
        status: test
        logsource:
            category: registry_set
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def registry_rename_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Registry Rename Test
        status: test
        logsource:
            category: registry_rename
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def create_stream_hash_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Create Stream Hash Test
        status: test
        logsource:
            category: create_stream_hash
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def dns_query_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Dns Query Test
        status: test
        logsource:
            category: dns_query
            product: windows
        detection:
            sel:
                QueryName: gist.github.com
            condition: sel
    """
    )


@pytest.fixture
def clipboard_capture_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Clipboard Capture Test
        status: test
        logsource:
            category: clipboard_capture
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def process_tampering_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Process Tampering Test
        status: test
        logsource:
            category: process_tampering
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """
    )


@pytest.fixture
def sysmon_error_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Sysmon Error Test
        status: test
        logsource:
            category: sysmon_error
            product: windows
        detection:
            sel:
                Description: a error is here
            condition: sel
    """
    )


@pytest.fixture
def sysmon_status_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Sysmon Status Test
        status: test
        logsource:
            category: sysmon_status
            product: windows
        detection:
            sel:
                State: a status is here
            condition: sel
    """
    )


@pytest.fixture
def sysmon_pipe_create_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Sysmon Status Test
        status: test
        logsource:
            category: pipe_created
            product: windows
        detection:
            sel:
                PipeName: a PipeName is here
            condition: sel
    """
    )


@pytest.fixture
def sysmon_wmi_event_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Sysmon Status Test
        status: test
        logsource:
            category: wmi_event
            product: windows
        detection:
            sel:
                Query: a wmi Query is here
            condition: sel
    """
    )


@pytest.fixture
def sysmon_file_delete_sigma_rule():
    return SigmaCollection.from_yaml(
        """
        title: Sysmon Status Test
        status: test
        logsource:
            category: file_delete
            product: windows
        detection:
            sel:
                TargetFilename: a file name is here
            condition: sel
    """
    )


def test_sysmon_process_creation(process_creation_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(process_creation_sigma_rule) == [
        'EventID=1 and CommandLine="test.exe foo bar" and Image endswith "\\test.exe"'
    ]


def test_sysmon_file_change(file_change_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(file_change_sigma_rule) == [
        'EventID=2 and TargetFilename="test"'
    ]


def test_sysmon_network_connect(network_connection_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(network_connection_sigma_rule) == [
        'EventID=3 and Initiated="true" and DestinationIp="1.2.3.4"'
    ]


def test_sysmon_process_termination(process_termination_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(process_termination_sigma_rule) == [
        'EventID=5 and Image="test.exe"'
    ]


def test_sysmon_driver_load(driver_load_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(driver_load_sigma_rule) == [
        'EventID=6 and ImageLoaded="test.exe"'
    ]


def test_sysmon_image_load(image_load_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(image_load_sigma_rule) == [
        'EventID=7 and ImageLoaded="test.exe"'
    ]


def test_sysmon_create_remote_thread(create_remote_thread_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(create_remote_thread_sigma_rule) == [
        'EventID=8 and SourceImage="test.exe"'
    ]


def test_sysmon_raw_access_thread(raw_access_thread_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(raw_access_thread_sigma_rule) == [
        'EventID=9 and Image="test.exe"'
    ]


def test_sysmon_process_access(process_access_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(process_access_sigma_rule) == [
        'EventID=10 and TargetImage="test.exe"'
    ]


def test_sysmon_file_event(file_event_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(file_event_sigma_rule) == [
        'EventID=11 and TargetFilename="test.exe"'
    ]


def test_sysmon_registry_event(registry_event_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(registry_event_sigma_rule) == [
        '(EventID in (12, 13, 14)) and Image="test.exe"'
    ]


def test_sysmon_registry_add(registry_add_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(registry_add_sigma_rule) == [
        'EventID=12 and Image="test.exe"'
    ]


def test_sysmon_registry_delete(registry_delete_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(registry_delete_sigma_rule) == [
        'EventID=12 and Image="test.exe"'
    ]


def test_sysmon_registry_set(registry_set_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(registry_set_sigma_rule) == [
        'EventID=13 and Image="test.exe"'
    ]


def test_sysmon_registry_rename(registry_rename_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(registry_rename_sigma_rule) == [
        'EventID=14 and Image="test.exe"'
    ]


def test_sysmon_create_stream_hash(create_stream_hash_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(create_stream_hash_sigma_rule) == [
        'EventID=15 and Image="test.exe"'
    ]


def test_sysmon_dns_query(dns_query_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(dns_query_sigma_rule) == [
        'EventID=22 and QueryName="gist.github.com"'
    ]


def test_sysmon_clipboard_capture(clipboard_capture_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(clipboard_capture_sigma_rule) == [
        'EventID=24 and Image="test.exe"'
    ]


def test_sysmon_process_tampering(process_tampering_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(process_tampering_sigma_rule) == [
        'EventID=25 and Image="test.exe"'
    ]


def test_sysmon_sysmon_error(sysmon_error_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(sysmon_error_sigma_rule) == [
        'EventID=255 and Description="a error is here"'
    ]


def test_sysmon_sysmon_status(sysmon_status_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(sysmon_status_sigma_rule) == [
        '(EventID in (4, 16)) and State="a status is here"'
    ]


def test_sysmon_pipe_create(sysmon_pipe_create_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(sysmon_pipe_create_sigma_rule) == [
        '(EventID in (17, 18)) and PipeName="a PipeName is here"'
    ]


def test_sysmon_wmi_event(sysmon_wmi_event_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(sysmon_wmi_event_sigma_rule) == [
        '(EventID in (19, 20, 21)) and Query="a wmi Query is here"'
    ]


def test_sysmon_file_delete(sysmon_file_delete_sigma_rule):
    backend = TextQueryTestBackend(sysmon_pipeline())
    assert backend.convert(sysmon_file_delete_sigma_rule) == [
        '(EventID in (23, 26)) and TargetFilename="a file name is here"'
    ]
