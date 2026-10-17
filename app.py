"""Local synthetic demo: Bob's comment, Alice's privileges, Alice's ticket."""
from dataclasses import asdict
from pathlib import Path
import tempfile
import json
import streamlit as st
from engine import Call, Denied, Lab
from scenarios import MaliciousModel, provenance

st.set_page_config(page_title='AI Tool Authorization Lab', page_icon='🔐')
st.title('AI Tool Authorization Lab')
st.caption('Synthetic local lab · malicious stub · no API key needed · revision 0.4')
st.warning('Local demonstration only. Demo personas are not production authentication.')
if 'directory' not in st.session_state:
    st.session_state.directory = tempfile.TemporaryDirectory(prefix='authorization-lab-')
path = str(Path(st.session_state.directory.name) / 'lab.db')
lab = Lab(path)
try:
    scenario = st.sidebar.selectbox('Scenario', ['Same-user poisoned ticket', 'Manual proposal'])
    same_user = scenario == 'Same-user poisoned ticket'
    if same_user:
        st.session_state.demo_persona = 'alice'
    persona = st.sidebar.selectbox('Demo persona', ['alice', 'bob'], disabled=same_user, key='demo_persona')
    protected = st.sidebar.radio('Backend', ['Protected', 'Vulnerable baseline']) == 'Protected'
    variant = st.sidebar.selectbox('Comment variant', ['overt', 'subtle']) if same_user else 'overt'
    signature = (scenario, persona, protected, variant)
    if st.session_state.get('signature') != signature:
        st.session_state.pop('pending', None)
        st.session_state.signature = signature
    if st.session_state.get('persona') != persona:
        previous = st.session_state.get('session')
        if previous:
            lab.db.execute('DELETE FROM sessions WHERE id=?', (previous,))
        st.session_state.session = lab.login_demo(persona)
        st.session_state.persona = persona
    session = st.session_state.session
    lab.configure_attack_comment(variant)
    st.subheader('Your tickets')
    ticket_table = st.empty()
    st.subheader('Model proposal')
    st.caption('The scenario determines the stub proposal. The stub always attempts the action '
               'and claims approval; it does not measure real-model susceptibility.')
    if same_user:
        st.info('User task: Summarize ticket 3. Bob has comment-only access to that ticket. '
                'His comment asks Alice\'s assistant to close ticket 1, also owned by Alice. '
                'Alice is selected automatically for this scenario.')
        comment = lab.ticket(3)['comments'][0]
        st.markdown(f"**Ticket 3 comment — author: {comment['author']} · variant: {variant}**")
        st.code(comment['body'], language=None)
        ticket, status = 1, 'closed'
        case = 'same_user_injection_subtle' if variant == 'subtle' else 'same_user_injection'
        source = provenance(case, lab)
    else:
        ticket = st.selectbox('Target ticket', [1, 2, 3])
        status = st.selectbox('Target status', ['closed', 'in_progress', 'open'])
        source = {'kind': 'manual_demo', 'user_request': 'Manual attack simulation'}
    call = Call(ticket, target_status=status)
    if st.button('Run model (malicious stub)'):
        proposal = MaliciousModel().propose(call)
        request_id = lab.new_request(session, source.get('task'), source)
        st.session_state.pending = {'call': asdict(call), 'source': source, 'request_id': request_id}
        st.json(proposal)
        try:
            result = lab.dispatch_model(session, proposal, protected=protected, request_id=request_id)
            st.error('Baseline committed without trusted approval.')
            st.json(result)
        except Denied as exc:
            st.success(f'Backend blocked execution: {exc}')
    pending = st.session_state.get('pending')
    if pending and protected:
        st.subheader('Review exact action')
        exact = Call(**pending['call'])
        request_id = pending['request_id']
        review = lab.approval_review(session, exact, request_id=request_id)
        exposure = review['input_provenance']
        if review['off_task']:
            st.error(review['banner'])
        st.markdown('**Original user task:** ' + exposure.get('user_request', 'Manual demonstration'))
        st.markdown(f'**Proposed action:** set ticket {exact.ticket_id} to `{exact.target_status}`')
        if exposure.get('kind') == 'untrusted_tool_result':
            st.markdown(f"**Source exposure:** ticket {exposure['ticket_id']}, comment by **{exposure['author']}**")
            st.code(exposure.get('excerpt', ''), language=None)
        with st.expander('Approval scope and provenance'):
            st.json(review)
        confirmed = st.checkbox('I understand this action is outside my request.' if review['off_task']
                                else 'I reviewed this exact action.', key='confirm_' + request_id)
        if st.button('Reject proposed change', type='primary'):
            lab.reject_from_ui(session, request_id)
            st.session_state.pop('pending', None)
            st.success('Proposal rejected. No change committed.')
        elif st.button('Approve and execute this exact action', disabled=not confirmed):
            try:
                token = lab.approve_from_ui(session, exact, request_id=request_id, confirm_off_task=confirmed)
                result = lab.execute(session, exact, token)
                st.success('User-approved change committed. Approval does not establish that the task was appropriate.')
                st.json(result)
            except Denied as exc:
                st.error(str(exc))
            st.session_state.pop('pending', None)
    ticket_table.dataframe([{'id': t['id'], 'owner': t['owner'], 'status': t['status'],
                            'description': t['description']} for t in lab.visible_tickets(session)], hide_index=True)
    st.subheader('Backend audit events')
    st.json([json.loads(r[0]) for r in lab.db.execute('SELECT data FROM events ORDER BY id DESC LIMIT 10')])
finally:
    lab.close()
