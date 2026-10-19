from unittest.mock import MagicMock
from app.priority_view import load_priority,present_findings


def test_failed_evaluation_hides_old_database_priorities():
    conn=MagicMock()
    state,result=load_priority(conn,'scan',{'priority':{'status':'invalid_input','current_result_available':False}})
    items=[{'finding_id':'f','packages':[{'package_id':'p','priority':'P0','fixed_version_candidates':[]}]}]
    present_findings(items,state,result)
    assert items[0]['packages'][0]['priority'] is None
    assert items[0]['priority_evaluation_status']=='invalid_input'
    conn.cursor.assert_not_called()


def test_no_marker_is_not_computed_even_with_old_values():
    state,result=load_priority(MagicMock(),'scan',{})
    assert state['status']=='not_computed'
    assert result is None


def test_rank_and_priority_come_from_same_published_link():
    items=[{'finding_id':'f','packages':[{'package_id':'p','priority':'P0'}]}]
    result={'link_results':[{'finding_id':'f','package_id':'p','priority':'P2','priority_status':'calculated',
                             'priority_rule_version':'v1','fix_information':'not_reported'}]}
    present_findings(items,{'status':'completed'},result)
    assert items[0]['packages'][0]['priority']=='P2'
    assert items[0]['priority_rank']==0
