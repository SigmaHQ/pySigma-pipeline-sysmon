from typing import Callable, Dict
from .sysmon import sysmon_pipeline
from sigma.processing.pipeline import ProcessingPipeline

pipelines : Dict[str, Callable[[], ProcessingPipeline]] = {
    "sysmon": sysmon_pipeline,
}