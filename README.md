![Tests](https://github.com/SigmaHQ/pySigma-pipeline-sysmon/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/9c695cb26aae10cb8107941388340ec1/raw)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Sysmon Processing Pipeline

This is the Sysmon processing pipeline for pySigma. It provides the package `sigma.pipeline.sysmon` with the `sysmon_pipeline` function that returns a ProcessingPipeline object.

Currently the pipeline adds support for the following event types (Sigma logsource category to EventID mapping):

* process_creation: 1
* file_change: 2
* network_connection: 3

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/thomaspatzke/)