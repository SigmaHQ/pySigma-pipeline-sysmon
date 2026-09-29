![Tests](https://github.com/SigmaHQ/pySigma-pipeline-sysmon/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/9c695cb26aae10cb8107941388340ec1/raw)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Sysmon Processing Pipeline

This is the [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) processing pipeline for pySigma. It provides the package `sigma.pipeline.sysmon` with the `sysmon_pipeline` function that returns a ProcessingPipeline object.

Only rules with `product: windows` and one of the categories listed below are transformed. Rules with
any other log source (for example the Windows categories `file_access`, `file_rename` and the
PowerShell `ps_*` categories, which Sysmon does not log) are passed through unchanged: no EventID
condition is added, the log source is not changed and no error is raised. Unless another pipeline in
the chain handles these log sources, the generated query contains only the rule's own detection
logic (e.g. `CommandLine="foo"`) and is not restricted to any event source. Select rules by log source
before conversion if your data only contains Sysmon events.

Currently the pipeline adds support for the following event types (Sigma logsource category to EventID mapping):

* process_creation: 1
* file_change: 2
* network_connection: 3
* process_termination: 5
* sysmon_status: 4,16
* driver_load: 6
* image_load: 7
* create_remote_thread: 8
* raw_access_thread: 9
* process_access: 10
* file_event: 11
* registry_add: 12
* registry_delete: 12
* registry_set: 13
* registry_rename: 14
* registry_event: 12,13,14
* create_stream_hash: 15
* pipe_created: 17,18
* wmi_event: 19,20,21
* dns_query: 22
* file_delete: 23
* clipboard_capture: 24
* process_tampering: 25
* file_delete_detected: 26
* file_block_executable: 27
* file_block_shredding: 28
* file_executable_detected: 29
* sysmon_error: 255

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/thomaspatzke/)
