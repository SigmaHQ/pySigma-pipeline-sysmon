from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

sysmon_generic_logsource_eventid_mapping = {    # map generic Sigma log sources to Sysmon event ids
    "process_creation": 1,
    "file_change": 2,
    "network_connection": 3,
    "process_termination": 5,
    "driver_load": 6,
    "image_load": 7,
    "create_remote_thread": 8,
    "raw_access_thread": 9,
    "process_access": 10,
    "file_event": 11,
    "create_stream_hash": 15,
    "dns_query": 22,
    "clipboard_capture": 24,
    "process_tampering": 25,
    "sysmon_error": 255,
}

def sysmon_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to Sysmon Transformation",
        priority=10,
        items=[
            processing_item
            for log_source, event_id in sysmon_generic_logsource_eventid_mapping.items()
            for processing_item in (
                ProcessingItem(
                    identifier=f"sysmon_{log_source}_eventid",
                    transformation=AddConditionTransformation({
                        "EventID": event_id,
                    }),
                    rule_conditions=[
                        LogsourceCondition(
                            category=log_source,
                            product="windows"
                        )
                    ]
                ),
                ProcessingItem(
                    identifier="sysmon_process_creation_logsource",
                    transformation=ChangeLogsourceTransformation(
                        product="windows",
                        service="sysmon",
                        category=log_source,
                    ),
                    rule_conditions=[
                        LogsourceCondition(
                            category=log_source,
                            product="windows"
                        )
                    ]
                )
            )
        ]
    )