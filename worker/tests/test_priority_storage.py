from copy import deepcopy
from uuid import uuid4
import pytest

from worker.app.priority_storage import build_payload
from worker.app.priority import PriorityInputError, calculate_priorities


def source():
    fid,pid=str(uuid4()),str(uuid4())
    return {'scan_id':str(uuid4()),'packages':[{'package_id':pid,'name':'demo','installed_version':'1.0.0','relationship':'indirect'}],
        'findings':[{'finding_id':fid,'severity':'CRITICAL','evidence':{'normalized':{
            'priority_input_eligible':True,'severity_observations':[]}}}],
        'finding_packages':[{'finding_id':fid,'package_id':pid,'fixed_version_candidates':[],
                             'evidence':{'fix_information':'not_reported'}}],
        'tool_status':{'package_storage':{'status':'completed'},'normalization':{
            'status':'partial','roundtrip_verified':True,
            'tool_status':{'trivy':{'status':'failed'},'osv':{'status':'completed'}}}}}


def test_normalized_status_not_process_status_controls_completeness():
    value=source()
    value['tool_status']['trivy']={'status':'completed'}
    before=deepcopy(value)
    result=calculate_priorities(build_payload(value))
    assert result['security_status']=='partial'
    assert result['link_results'][0]['priority']=='P0'
    assert result['link_results'][0]['fix_information']=='not_reported'
    assert value==before


def test_old_metadata_is_rejected_without_rewriting_evidence():
    value=source()
    value['findings'][0]['evidence']['normalized'].pop('priority_input_eligible')
    with pytest.raises(PriorityInputError,match='LEGACY_SOURCE'):
        build_payload(value)


def test_missing_normalization_cannot_claim_zero_findings():
    value=source()
    value['tool_status']['normalization']={'status':'failed'}
    with pytest.raises(PriorityInputError,match='SOURCE_NOT_READY'):
        build_payload(value)
