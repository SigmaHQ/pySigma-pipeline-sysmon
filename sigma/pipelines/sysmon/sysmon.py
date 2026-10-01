from sigma.processing.transformations import (
    AddConditionTransformation,
    ChangeLogsourceTransformation,
)
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

sysmon_generic_logsource_eventid_mapping = (
    {  # map generic Sigma log sources to Sysmon event ids
        "process_creation": 1,
        "file_change": 2,
        "network_connection": 3,
        "sysmon_status": [4, 16],
        "process_termination": 5,
        "driver_load": 6,
        "image_load": 7,
        "create_remote_thread": 8,
        "raw_access_thread": 9,
        "process_access": 10,
        "file_event": 11,
        "registry_add": 12,
        "registry_delete": 12,
        "registry_set": 13,
        "registry_rename": 14,
        "registry_event": [12, 13, 14],
        "create_stream_hash": 15,
        "pipe_created": [17, 18],
        "wmi_event": [19, 20, 21],
        "dns_query": 22,
        "file_delete": 23,
        "clipboard_capture": 24,
        "process_tampering": 25,
        "file_delete_detected": 26,
        "file_block_executable": 27,
        "file_block_shredding": 28,
        "file_executable_detected": 29,
        "sysmon_error": 255,
    }
)

# Sysmon event ID 12 covers both registry object creation and deletion; its EventType field tells
# them apart (CreateKey, DeleteKey or DeleteValue; value creation is event ID 13, SetValue).
sysmon_generic_logsource_additional_conditions = {
    "registry_add": {"EventType": "CreateKey"},
    "registry_delete": {"EventType": ["DeleteKey", "DeleteValue"]},
}


# Deliberately not decorated with @Pipeline: that decorator is a process-wide singleton in
# pySigma, so every decorated function aliases the same object and the last one decorated
# wins. Plugin autodiscovery finds this function through its ProcessingPipeline return type.
def sysmon_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="Generic Log Sources to Sysmon Transformation",
        # Must run strictly before the priority-10 pipelines (e.g. windows-logsources) that add
        # the Channel condition for the service: sysmon log source this pipeline sets.
        priority=5,
        items=[
            processing_item
            for log_source, event_id in sysmon_generic_logsource_eventid_mapping.items()
            for processing_item in (
                ProcessingItem(
                    identifier=f"sysmon_{log_source}_eventid",
                    transformation=AddConditionTransformation(
                        {
                            "EventID": event_id,
                            **sysmon_generic_logsource_additional_conditions.get(
                                log_source, {}
                            ),
                        }
                    ),
                    rule_conditions=[
                        LogsourceCondition(category=log_source, product="windows")
                    ],
                ),
                ProcessingItem(
                    identifier=f"sysmon_{log_source}_logsource",
                    transformation=ChangeLogsourceTransformation(
                        product="windows",
                        service="sysmon",
                        category=log_source,
                    ),
                    rule_conditions=[
                        LogsourceCondition(category=log_source, product="windows")
                    ],
                ),
            )
        ],
    )
