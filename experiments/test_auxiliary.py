import unittest
from auxiliary_campaign import validate_utility
import json
class AuxiliaryTests(unittest.TestCase):
 def test_unknown_is_not_success(self):
  result=validate_utility(json.dumps({'items':[None],'evidence':[''],'unsupported_material_fact':False}), 'record',{'essential_items':['fact']})
  self.assertTrue(result['unresolved']);self.assertFalse(result['complete'])
 def test_positive_requires_literal_evidence(self):
  with self.assertRaises(ValueError):validate_utility(json.dumps({'items':[True],'evidence':['absent'],'unsupported_material_fact':False}), 'record',{'essential_items':['fact']})
 def test_complete_requires_no_material_hallucination(self):
  result=validate_utility(json.dumps({'items':[True],'evidence':['record'],'unsupported_material_fact':True}), 'record',{'essential_items':['fact']})
  self.assertFalse(result['complete'])
if __name__=='__main__':unittest.main()
