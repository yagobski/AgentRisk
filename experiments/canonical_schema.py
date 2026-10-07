"""Validated Table 5 export of archived internal detector observations."""
from copy import deepcopy
import math

ALIASES = {'channel': 'channel_id', 'detector': 'detector_source',
           'severity': 'severity_level'}
REQUIRED = {'trace_id', 'channel_id', 'secret_id', 'disclosed',
            'severity_level', 'task_required', 'detector_source', 'scope_id'}


def validate(record):
    """Validate the observation contract; do not infer exposure or policy labels."""
    if not isinstance(record, dict) or not REQUIRED <= record.keys():
        raise ValueError('Missing required canonical fields')
    for field in ('trace_id', 'channel_id', 'secret_id', 'detector_source', 'scope_id'):
        if not isinstance(record[field], str) or not record[field].strip():
            raise ValueError('Empty or invalid identity: ' + field)
    if record['disclosed'] is not None and type(record['disclosed']) is not bool:
        raise ValueError('disclosed must be true, false or null')
    if type(record['severity_level']) is not int or record['severity_level'] not in (1, 2, 3, 4):
        raise ValueError('severity_level must be an integer tier from 1 to 4')
    if record['task_required'] not in ('yes', 'no', 'unsure'):
        raise ValueError('task_required must be yes, no or unsure')
    provenance = record.get('task_required_provenance')
    if not isinstance(provenance, str) or not provenance.strip():
        raise ValueError('Task-necessity provenance is required')
    if 'confidence' in record:
        confidence = record['confidence']
        if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError('confidence must be finite and between 0 and 1')
    if record['disclosed'] is True:
        evidence = record.get('evidence')
        text_span = isinstance(evidence, str) and bool(evidence.strip())
        spans = (isinstance(evidence, list) and bool(evidence)
                 and all(isinstance(span, dict) and isinstance(span.get('text'), str)
                         and bool(span['text'].strip()) for span in evidence))
        if not (text_span or spans):
            raise ValueError('Resolved positives require literal evidence')
    return record


def to_canonical(record):
    """Map internal aliases and absent adjudication without changing detection."""
    result = deepcopy(record)
    for internal, canonical in ALIASES.items():
        if internal in result:
            if canonical in result and (type(result[canonical]) is not type(result[internal])
                                        or result[canonical] != result[internal]):
                raise ValueError('Conflicting alias: ' + internal)
            result[canonical] = result.pop(internal)
    if 'task_required' not in result:
        raise ValueError('Missing task_required')
    status = result.get('task_required_status')
    if result['task_required'] is None:
        if status != 'independent contextual annotation unavailable':
            raise ValueError('Null task_required needs explicit unavailable-adjudication provenance')
        result['task_required'] = 'unsure'
        result['task_required_provenance'] = status
    elif 'task_required_provenance' not in result and isinstance(status, str):
        result['task_required_provenance'] = status
    return validate(result)
