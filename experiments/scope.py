"""Exact-ID scope fixtures. These tests are not evidence of deployed multi-hop accuracy."""


def replay(events):
    access, retained, snapshots = {}, {}, []
    last = -1
    for event in events:
        if event['sequence'] <= last:
            raise ValueError('Non-increasing event sequence')
        last = event['sequence']
        agent = event['agent']; kind = event['kind']; ids = set(event.get('secrets', []))
        access.setdefault(agent,set()); retained.setdefault(agent,set())
        if kind == 'grant':
            access[agent] |= ids
        elif kind == 'revoke':
            access[agent] -= ids  # Knowledge already retained survives permission changes.
        elif kind == 'retrieve':
            if not ids <= access[agent]:
                raise ValueError('Retrieval without access')
            retained[agent] |= ids
        elif kind == 'receive':
            retained[agent] |= ids
        elif kind == 'clear':
            if not event.get('deletion_evidence'):
                raise ValueError('Clearing retained knowledge requires evidence')
            retained[agent] -= ids
        elif kind == 'handoff':
            scope = access[agent] | retained[agent]
            if not ids <= retained[agent]:
                raise ValueError('Cannot transmit a secret not observed in retained knowledge')
            snapshots.append({'sequence':last,'agent':agent,'recipient':event['recipient'],
                              'inventory':sorted(scope),'observed_knowledge':sorted(retained[agent]),
                              'exposed':sorted(ids)})
            retained.setdefault(event['recipient'],set()).update(ids)
        else:
            raise ValueError('Unknown scope event')
    return snapshots
