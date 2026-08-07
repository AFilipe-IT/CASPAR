"""
config_assessment/api
----------------------
REST API interface for the CVM Core. Zero business logic — every route calls
into config_assessment.core.engines (or config_assessment.core.runtime for the
scan pipeline). The CLI and this API always produce identical results because
both call the same CVM Core.
"""
