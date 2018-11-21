#python은 기본적으로 json 표준 라이브러리 제공, 라이브러리 사용시 python타입의 object를 json문자열로 변경가능(json인코딩), 또한 json문자열을 다시 python타입으로 변환 가능(json디코딩)
import json
#uuid는 기본적으로 어떤 개체(데이터)를 고유하게 식별하는 데 사용되는 16바이트 길이의 숫 예 : 022db29c-d0e2-11e5-bb4c-60f81dca7676
import uuid
#객체를 복사하기 위한 용도
import copy
#로그를 찍기위한 라이브러리
import logging
#base64인코딩,디코딩을 위한 라이브러리
##인코딩 : 정보의 형태나 형식을 부호화/암호화시킨다, 디코딩 : 부호화/암호화를 해체한다
import base64
#정규 표현식을 지원하기 위해 제공되는 모
import re

#PynamoDB : 파이썬 2와 3을 지원하는 아마존의 DynamoDB의 Pythonic interface
#PutError->아이템이 생성 실패 시 "Error putting item"이란 말을 올린다.
#DoesNotExist->아이템의 쿼리가 존제하지 않을 시 "Item does not exitst"이란 말을 올린다.
from pynamodb.exceptions import PutError, DoesNotExist
#객체에 담긴 HTTP요청에 대한 상세를  request해주기 위해
from flask import request
#플라스크의 목록을 jsonify하기 위한 라이브러리
from flask import jsonify
#클라이언트오류에 대한 예외처리를 위한 라이브러리
from botocore.exceptions import ClientError

#confidant 외부 서비스에 접속을 위한 라이브러리(모듈)
import confidant.services
from confidant import keymanager
from confidant import authnz
from confidant import graphite
from confidant import settings
from confidant import webhook
from confidant.app import app
from confidant.utils import stats
from confidant.utils import maintenance
from confidant.ciphermanager import CipherManager
from confidant.models.credential import Credential
from confidant.models.blind_credential import BlindCredential
from confidant.models.service import Service

#iam_resource라는 변수에 iam리소스 값을 가져온다
iam_resource = confidant.services.get_boto_resource('iam')
#kms_client라는 변수에 클라이언트의 kms인증키를 받아온다
kms_client = confidant.services.get_boto_client('kms')

#VALUE_LENGTH변수에 50 대입
VALUE_LENGTH = 50

#로그인 흐름에 따라 유저 로그인 시키기 위한 함수 정의
@app.route('/v1/login', methods=['GET', 'POST'])
def login():
    '''
    Send user through login flow.
    '''
    return authnz.log_in()

#바로 최근에 로그인 된 유저로부터 이메일주소 정보 가져오기 없으면 None 가져오기 위한 함수 정의
@app.route('/v1/user/email', methods=['GET', 'POST'])
@authnz.require_auth
def get_user_info():
    '''
    Get the email address of the currently logged-in user.
    '''
    try:
        #email에 대한 JSON타입의 http response 생성된 값을 response변수에 대입
        response = jsonify({'email': authnz.get_logged_in_user()})
    except authnz.UserUnknownError:
        #UserUnknownError가 뜰 시 none을 response변수에 대입
        response = jsonify({'email': None})
    #response 변수 리턴
    return response

#클라이언트가 bootstrap하는 것을 도와주기 위해 configuration을 가져오기 위한 함수 정의
@app.route('/v1/client_config', methods=['GET'])
@authnz.require_auth
def get_client_config():
    '''
    Get configuration to help clients bootstrap themselves.
    '''
    # TODO: add more config in here.
    #configuration에 대한 JSON타입의 http response 생성된 값을 response변수에 대입
    response = jsonify({
        'defined': app.config['CLIENT_CONFIG'],
        'generated': {
            #kms인증키 가져오기
            'kms_auth_manage_grants': app.config['KMS_AUTH_MANAGE_GRANTS'],
            #aws계정 가져오기
            'aws_accounts': app.config['SCOPED_AUTH_KEYS'].values(),
            #쿠키 이름 가져오기
            'xsrf_cookie_name': app.config['XSRF_COOKIE_NAME'],
            #maintenance_mode 값 가져오기
            'maintenance_mode': app.config['MAINTENANCE_MODE']
        }
    })
    #response 변수 리턴
    return response

#service리스트 가져오기 위한 함수 정의
@app.route('/v1/services', methods=['GET'])
@authnz.require_auth
def get_service_list():
    #services라는 리스트 생성
    services = []
    #Service.data_type_date_index.query('service')양 만큼의 반복문이 실행되며 리스트에 id,account,enabled,revision,modified_date,modified_by를 추가한다
    for service in Service.data_type_date_index.query('service'):
        services.append({
            'id': service.id,
            'account': service.account,
            'enabled': service.enabled,
            'revision': service.revision,
            'modified_date': service.modified_date,
            'modified_by': service.modified_by
        })
    #리스트릴 jsonify시켜 리턴해준다.
    return jsonify({'services': services})


@app.route('/v1/roles', methods=['GET'])
@authnz.require_auth
#iam_roles_list를 가져오기 위한 함수 정의
def get_iam_roles_list():
    try:
        roles = [x.name for x in iam_resource.roles.all()]
    except ClientError:
        return jsonify({'error': 'Unable to roles.'}), 500
    return jsonify({'roles': roles})


@app.route('/v1/services/<id>', methods=['GET'])
@authnz.require_auth
#서비스의 메타데이타와 모든 credentials를 가져오기 위한 함수 정의
def get_service(id):
    '''
    Get service metadata and all credentials for this service. This endpoint
    allows basic authentication.
    '''
    #_init_.py에 정의된 user_is_user_type함수를 통해 service값이라면 제어문 안으로
    if authnz.user_is_user_type('service'):
        #_init_.py에 정의된 user_is_service함수를 통해 함수의 파라메터 값으로 받아온 id가 아니라면 로그에 'Authz failed for service {0}.', 'Authenticated user is not authorized.'라는 메시지와 함께 401error를 띄운다
        if not authnz.user_is_service(id):
            logging.warning('Authz failed for service {0}.'.format(id))
            msg = 'Authenticated user is not authorized.'
            return jsonify({'error': msg}), 401
    try:
        #service라는 변수에 id값 대입
        service = Service.get(id)
        #_init_.py에 정의된 service_in_account함수를 통해 account값이 일치하지 않는다면 제어문 안으로
        if not authnz.service_in_account(service.account):
            #아래와 같은 로그를 남긴다
            logging.warning(
                'Authz failed for service {0} (wrong account).'.format(id)
            )
            #msg에 아래와 같은 문자 대입
            msg = 'Authenticated user is not authorized.'
            #401error를 msg에 대입된 문자열과 함께 jsonify시켜 리턴
            return jsonify({'error': msg}), 401
    #위 try문의 코드에 error발생 시 예외처리
    except DoesNotExist:
        return jsonify({}), 404
    if (service.data_type != 'service' and
            service.data_type != 'archive-service'):
        return jsonify({}), 404
    logging.debug('Authz succeeded for service {0}.'.format(id))
    try:
        #credential을 가져온다
        credentials = _get_credentials(service.credentials)
    except KeyError:
        #error발생 시 500error발생
        logging.exception('KeyError occurred in getting credentials')
        return jsonify({'error': 'Decryption error.'}), 500
    blind_credentials = _get_blind_credentials(service.blind_credentials)
    return jsonify({
        'id': service.id,
        'account': service.account,
        'credentials': credentials,
        'blind_credentials': blind_credentials,
        'enabled': service.enabled,
        'revision': service.revision,
        'modified_date': service.modified_date,
        'modified_by': service.modified_by
    })


@app.route('/v1/archive/services/<id>', methods=['GET'])
@authnz.require_auth
#아카이브 서비스 revision(개정, 정정)가져오는 함수 정의
def get_archive_service_revisions(id):
    try:
        service = Service.get(id)
    except DoesNotExist:
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        #아이템 없으 시 404error
        return jsonify({}), 404
        #자료 형식 service와 일치하지 않을 시 404error
    if (service.data_type != 'service' and
            service.data_type != 'archive-service'):
        return jsonify({}), 404
    #revision list
    revisions = []
    _range = range(1, service.revision + 1)
    ids = []
    for i in _range:
        #ids리스트에 id들 _range정의된 범위만큼의 id추가
        ids.append("{0}-{1}".format(id, i))
    for revision in Service.batch_get(ids):
        #revisions리스트에 ids리스트 크기만큼 아래 내용 추가
        revisions.append({
            'id': revision.id,
            'account': revision.account,
            'revision': revision.revision,
            'enabled': revision.enabled,
            'credentials': list(revision.credentials),
            'blind_credentials': list(revision.blind_credentials),
            'modified_date': revision.modified_date,
            'modified_by': revision.modified_by
        })
    return jsonify({
        'revisions': sorted(
            revisions,
            key=lambda k: k['revision'],
            reverse=True
        )
    })

@app.route('/v1/archive/services', methods=['GET'])
@authnz.require_auth
#아카이브 서비스 리스트 가져오는 함수 정의
def get_archive_service_list():
    services = []
    for service in Service.data_type_date_index.query(
            'archive-service', scan_index_forward=False):
        services.append({
            'id': service.id,
            'account': service.account,
            'revision': service.revision,
            'enabled': service.enabled,
            'credentials': list(service.credentials),
            'modified_date': service.modified_date,
            'modified_by': service.modified_by
        })
    #servises jsonify시켜 리턴
    return jsonify({'services': services})


@app.route('/v1/grants/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
#해당 id에 아래 예외처리들로 안정성 부여하는 함수 정의
def ensure_grants(id):
    try:
        _service = Service.get(id)
        if _service.data_type != 'service':
            msg = 'id provided is not a service.'
            return jsonify({'error': msg}), 400
    except DoesNotExist:
        msg = 'id provided does not exist.'
        return jsonify({'error': msg}), 400
    try:
        keymanager.ensure_grants(id)
    except keymanager.ServiceCreateGrantError:
        msg = 'Failed to add grants for service.'
        logging.error(msg)
        return jsonify({'error': msg}), 400
    try:
        grants = keymanager.grants_exist(id)
    except keymanager.ServiceGetGrantError:
        msg = 'Failed to get grants.'
        return jsonify({'error': msg}), 500
    return jsonify({
        'id': id,
        'grants': grants
    })


@app.route('/v1/grants/<id>', methods=['GET'])
@authnz.require_auth
#해당 id grants 가져오는 함수 정의
def get_grants(id):
    try:
        _service = Service.get(id)
        if _service.data_type != 'service':
            msg = 'id provided is not a service.'
            return jsonify({'error': msg}), 400
    except DoesNotExist:
        msg = 'id provided does not exist.'
        return jsonify({'error': msg}), 400
    try:
        grants = keymanager.grants_exist(id)
    except keymanager.ServiceGetGrantError:
        msg = 'Failed to get grants.'
        return jsonify({'error': msg}), 500
    #id와 grants jsonify시켜 리턴
    return jsonify({
        'id': id,
        'grants': grants
    })


@app.route('/v1/services/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
#서비스의 credentials mapping 하는 함수 정의
def map_service_credentials(id):
    #json 데이터 받아오기
    data = request.get_json()
    try:
        _service = Service.get(id)
        #서비스가 아니라면 error
        if _service.data_type != 'service':
            msg = 'id provided is not a service.'
            return jsonify({'error': msg}), 400
        revision = _service.revision + 1
        _service_credential_ids = _service.credentials
    except DoesNotExist:
        revision = 1
        _service_credential_ids = []

#존제하는 credentials가 있다면 제어문 안으로
    if data.get('credentials') or data.get('blind_credentials'):
        conflicts = _pair_key_conflicts_for_credentials(
            data.get('credentials', []),
            data.get('blind_credentials', []),
        )
        if conflicts:
            ret = {
                'error': 'Conflicting key pairs in mapped service.',
                'conflicts': conflicts
            }
            return jsonify(ret), 400

    accounts = app.config['SCOPED_AUTH_KEYS'].values()
    if data.get('account') and data['account'] not in accounts:
        ret = {'error': '{0} is not a valid account.'}
        return jsonify(ret), 400

    # If this is the first revision, we should attempt to create a grant for
    # this service.
    #첫 번째 revision인 경우 허가를 부여하기 위한 예외처리
    if revision == 1:
        try:
            keymanager.ensure_grants(id)
        except keymanager.ServiceCreateGrantError:
            msg = 'Failed to add grants for {0}.'.format(id)
            logging.error(msg)
    # Try to save to the archive
    try:
        Service(
            id='{0}-{1}'.format(id, revision),
            data_type='archive-service',
            credentials=data.get('credentials'),
            blind_credentials=data.get('blind_credentials'),
            account=data.get('account'),
            enabled=data.get('enabled'),
            revision=revision,
            modified_by=authnz.get_logged_in_user()
        ).save(id__null=True)
    except PutError as e:
        logging.error(e)
        return jsonify({'error': 'Failed to add service to archive.'}), 500

    try:
        service = Service(
            id=id,
            data_type='service',
            credentials=data.get('credentials'),
            blind_credentials=data.get('blind_credentials'),
            account=data.get('account'),
            enabled=data.get('enabled'),
            revision=revision,
            modified_by=authnz.get_logged_in_user()
        )
        service.save()
    except PutError as e:
        logging.error(e)
        return jsonify({'error': 'Failed to update active service.'}), 500
    added = list(set(service.credentials) - set(_service_credential_ids))
    removed = list(set(_service_credential_ids) - set(service.credentials))
    msg = 'Added credentials: {0}; Removed credentials {1}; Revision {2}'
    msg = msg.format(added, removed, service.revision)
    graphite.send_event([id], msg)
    webhook.send_event('service_update', [service.id], service.credentials)
    try:
        credentials = _get_credentials(service.credentials)
    except KeyError:
        return jsonify({'error': 'Decryption error.'}), 500
    blind_credentials = _get_blind_credentials(service.blind_credentials)
    return jsonify({
        'id': service.id,
        'account': service.account,
        'credentials': credentials,
        'blind_credentials': blind_credentials,
        'revision': service.revision,
        'enabled': service.enabled,
        'modified_date': service.modified_date,
        'modified_by': service.modified_by
    })


@app.route('/v1/credentials', methods=['GET'])
@authnz.require_auth
#credential리스트 가져오기 함수 정의
def get_credential_list():
    credentials = []
    for cred in Credential.data_type_date_index.query('credential'):
        credentials.append({
            'id': cred.id,
            'name': cred.name,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })

    credentials = sorted(credentials, key=lambda k: k['name'])
    return jsonify({'credentials': credentials})


@app.route('/v1/credentials/<id>', methods=['GET'])
@authnz.require_auth
#credential id가져오기 함수 정의
def get_credential(id):
    try:
        cred = Credential.get(id)
    except DoesNotExist:
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (cred.data_type != 'credential' and
            cred.data_type != 'archive-credential'):
        return jsonify({}), 404
    services = []
    for service in Service.data_type_date_index.query('service'):
        services.append(service.id)
    if cred.data_type == 'credential':
        context = id
    else:
        context = id.split('-')[0]
    data_key = keymanager.decrypt_datakey(
        cred.data_key,
        encryption_context={'id': context}
    )
    cipher_version = cred.cipher_version
    cipher = CipherManager(data_key, cipher_version)
    _credential_pairs = cipher.decrypt(cred.credential_pairs)
    _credential_pairs = json.loads(_credential_pairs)
    return jsonify({
        'id': id,
        'name': cred.name,
        'credential_pairs': _credential_pairs,
        'metadata': cred.metadata,
        'services': services,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/archive/credentials/<id>', methods=['GET'])
@authnz.require_auth
#아카이브 credential revisions 가져오기 함수 정의
def get_archive_credential_revisions(id):
    try:
        cred = Credential.get(id)
    except DoesNotExist:
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (cred.data_type != 'credential' and
            cred.data_type != 'archive-credential'):
        return jsonify({}), 404
    revisions = []
    _range = range(1, cred.revision + 1)
    ids = []
    for i in _range:
        ids.append("{0}-{1}".format(id, i))
    for revision in Credential.batch_get(ids):
        revisions.append({
            'id': revision.id,
            'name': revision.name,
            'revision': revision.revision,
            'enabled': revision.enabled,
            'modified_date': revision.modified_date,
            'modified_by': revision.modified_by,
            'documentation': revision.documentation
        })
    return jsonify({
        'revisions': sorted(
            revisions,
            key=lambda k: k['revision'],
            reverse=True
        )
    })


@app.route('/v1/archive/credentials', methods=['GET'])
@authnz.require_auth
#아카이브 credential list 가져오기 함수 정의
def get_archive_credential_list():
    credentials = []
    for cred in Credential.data_type_date_index.query(
            'archive-credential', scan_index_forward=False):
        credentials.append({
            'id': cred.id,
            'name': cred.name,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })
    return jsonify({'credentials': credentials})

#credentials 가져오는 함수 정의
def _get_credentials(credential_ids):
    credentials = []
    with stats.timer('service_batch_get_credentials'):
        for cred in Credential.batch_get(copy.deepcopy(credential_ids)):
            data_key = keymanager.decrypt_datakey(
                cred.data_key,
                encryption_context={'id': cred.id}
            )
            cipher_version = cred.cipher_version
            cipher = CipherManager(data_key, cipher_version)
            _credential_pairs = cipher.decrypt(cred.credential_pairs)
            _credential_pairs = json.loads(_credential_pairs)
            credentials.append({
                'id': cred.id,
                'data_type': 'credential',
                'name': cred.name,
                'enabled': cred.enabled,
                'revision': cred.revision,
                'credential_pairs': _credential_pairs,
                'metadata': cred.metadata,
                'documentation': cred.documentation
            })
    return credentials

#blind_credentials 가져오는 함수 정의
def _get_blind_credentials(credential_ids):
    credentials = []
    with stats.timer('service_batch_get_blind_credentials'):
        for cred in BlindCredential.batch_get(copy.deepcopy(credential_ids)):
            credentials.append({
                'id': cred.id,
                'data_type': 'blind-credential',
                'name': cred.name,
                'enabled': cred.enabled,
                'revision': cred.revision,
                'credential_pairs': cred.credential_pairs,
                'credential_keys': list(cred.credential_keys),
                'metadata': cred.metadata,
                'data_key': cred.data_key,
                'cipher_version': cred.cipher_version,
                'cipher_type': cred.cipher_type,
                'documentation': cred.documentation
            })
    return credentials

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
def _pair_key_conflicts_for_credentials(credential_ids, blind_credential_ids):
    #conflicts, pair_keys 라는 dictionary생성(key-value)
    conflicts = {}
    pair_keys = {}
    # If we don't care about conflicts, return immediately
    #conflicts에 대하여 상관하지않는다면 즉시 리턴
    if app.config['IGNORE_CONFLICTS']:
        return conflicts
    # For all credentials, get their credential pairs and track which
    # 모든 credentials에 대해서, 각각의 credential 쌍을 얻는다
    # credentials have which keys
    #credential이 which keys를 가지고 있다.
    credentials = _get_credentials(credential_ids)
    credentials.extend(_get_blind_credentials(blind_credential_ids))
    for credential in credentials:
        if credential['data_type'] == 'credential':
            keys = credential['credential_pairs']
        elif credential['data_type'] == 'blind-credential':
            keys = credential['credential_keys']
        for key in keys:
            data = {
                'id': credential['id'],
                'data_type': credential['data_type']
            }
            if key in pair_keys:
                pair_keys[key].append(data)
            else:
                pair_keys[key] = [data]
    # Iterate the credential pair keys, if there's any keys with more than
    # one credential add it to the conflict dict.
    ###############
    ###############
    for key, data in pair_keys.iteritems():
        if len(data) > 1:
            blind_ids = [k['id'] for k in data
                         if k['data_type'] == 'blind-credential']
            ids = [k['id'] for k in data if k['data_type'] == 'credential']
            conflicts[key] = {
                'credentials': ids,
                'blind_credentials': blind_ids
            }
    return conflicts


def _get_services_for_credential(_id):
    services = []
    for service in Service.data_type_date_index.query('service'):
        if _id in service.credentials:
            services.append(service)
    return services


def _get_services_for_blind_credential(_id):
    services = []
    for service in Service.data_type_date_index.query('service'):
        if _id in service.blind_credentials:
            services.append(service)
    return services


def _check_credential_pair_values(credential_pairs):
    for key, val in credential_pairs.iteritems():
        if isinstance(val, dict) or isinstance(val, list):
            ret = {'error': 'credential pairs must be key: value'}
            return (False, ret)
    return (True, {})


def _get_service_map(services):
    service_map = {}
    for service in services:
        for credential in service.credentials:
            if credential in service_map:
                service_map[credential]['service_ids'].append(service.id)
            else:
                service_map[credential] = {
                    'data_type': 'credential',
                    'service_ids': [service.id]
                }
        for credential in service.blind_credentials:
            if credential in service_map:
                service_map[credential]['service_ids'].append(service.id)
            else:
                service_map[credential] = {
                    'data_type': 'blind-credential',
                    'service_ids': [service.id]
                }
    return service_map


def _pair_key_conflicts_for_services(_id, credential_keys, services):
    conflicts = {}
    # If we don't care about conflicts, return immediately
    if app.config['IGNORE_CONFLICTS']:
        return conflicts
    service_map = _get_service_map(services)
    credential_ids = []
    blind_credential_ids = []
    for credential, data in service_map.iteritems():
        if _id == credential:
            continue
        if data['data_type'] == 'credential':
            credential_ids.append(credential)
        elif data['data_type'] == 'blind-credential':
            blind_credential_ids.append(credential)
    credentials = _get_credentials(credential_ids)
    credentials.extend(_get_blind_credentials(blind_credential_ids))
    for credential in credentials:
        services = service_map[credential['id']]['service_ids']
        if credential['data_type'] == 'credential':
            data_type = 'credentials'
            lookup = 'credential_pairs'
        elif credential['data_type'] == 'blind-credential':
            data_type = 'blind_credentials'
            lookup = 'credential_keys'
        for key in credential_keys:
            if key in credential[lookup]:
                if key not in conflicts:
                    conflicts[key] = {
                        data_type: [credential['id']],
                        'services': services
                    }
                else:
                    conflicts[key]['services'].extend(services)
                    conflicts[key][data_type].append(credential['id'])
                conflicts[key]['services'] = list(
                    set(conflicts[key]['services'])
                )
                conflicts[key][data_type] = list(
                    set(conflicts[key][data_type])
                )
    return conflicts


def _lowercase_credential_pairs(credential_pairs):
    return {i.lower(): j for i, j in credential_pairs.iteritems()}


@app.route('/v1/credentials', methods=['POST'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def create_credential():
    data = request.get_json()
    if not data.get('documentation') and settings.get('ENFORCE_DOCUMENTATION'):
        return jsonify({'error': 'documentation is a required field'}), 400
    if not data.get('credential_pairs'):
        return jsonify({'error': 'credential_pairs is a required field'}), 400
    if not isinstance(data.get('metadata', {}), dict):
        return jsonify({'error': 'metadata must be a dict'}), 400
    # Ensure credential pair keys are lowercase
    credential_pairs = _lowercase_credential_pairs(data['credential_pairs'])
    _check, ret = _check_credential_pair_values(credential_pairs)
    if not _check:
        return jsonify(ret), 400
    for cred in Credential.data_type_date_index.query(
            'credential', name__eq=data['name']):
        # Conflict, the name already exists
        msg = 'Name already exists. See id: {0}'.format(cred.id)
        return jsonify({'error': msg, 'reference': cred.id}), 409
    # Generate an initial stable ID to allow name changes
    id = str(uuid.uuid4()).replace('-', '')
    # Try to save to the archive
    revision = 1
    credential_pairs = json.dumps(credential_pairs)
    data_key = keymanager.create_datakey(encryption_context={'id': id})
    cipher = CipherManager(data_key['plaintext'], version=2)
    credential_pairs = cipher.encrypt(credential_pairs)
    cred = Credential(
        id='{0}-{1}'.format(id, revision),
        data_type='archive-credential',
        name=data['name'],
        credential_pairs=credential_pairs,
        metadata=data.get('metadata'),
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data_key['ciphertext'],
        cipher_version=2,
        modified_by=authnz.get_logged_in_user(),
        documentation=data.get('documentation')
    ).save(id__null=True)
    # Make this the current revision
    cred = Credential(
        id=id,
        data_type='credential',
        name=data['name'],
        credential_pairs=credential_pairs,
        metadata=data.get('metadata'),
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data_key['ciphertext'],
        cipher_version=2,
        modified_by=authnz.get_logged_in_user(),
        documentation=data.get('documentation')
    )
    cred.save()
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': json.loads(cipher.decrypt(cred.credential_pairs)),
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/credentials/<id>/services', methods=['GET'])
@authnz.require_auth
def get_credential_dependencies(id):
    services = _get_services_for_credential(id)
    _services = [{'id': x.id, 'enabled': x.enabled} for x in services]
    return jsonify({
        'services': _services
    })


@app.route('/v1/credentials/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def update_credential(id):
    try:
        _cred = Credential.get(id)
    except DoesNotExist:
        return jsonify({'error': 'Credential not found.'}), 404
    if _cred.data_type != 'credential':
        msg = 'id provided is not a credential.'
        return jsonify({'error': msg}), 400
    data = request.get_json()
    update = {}
    revision = _get_latest_credential_revision(id, _cred.revision)
    update['name'] = data.get('name', _cred.name)
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return jsonify({'error': 'Enabled must be a boolean.'}), 400
        update['enabled'] = data['enabled']
    else:
        update['enabled'] = _cred.enabled
    if not isinstance(data.get('metadata', {}), dict):
        return jsonify({'error': 'metadata must be a dict'}), 400
    services = _get_services_for_credential(id)
    if 'credential_pairs' in data:
        # Ensure credential pair keys are lowercase
        credential_pairs = _lowercase_credential_pairs(
            data['credential_pairs']
        )
        _check, ret = _check_credential_pair_values(credential_pairs)
        if not _check:
            return jsonify(ret), 400
        # Ensure credential pairs don't conflicts with pairs from other
        # services
        conflicts = _pair_key_conflicts_for_services(
            id,
            credential_pairs.keys(),
            services
        )
        if conflicts:
            ret = {
                'error': 'Conflicting key pairs in mapped service.',
                'conflicts': conflicts
            }
            return jsonify(ret), 400
        update['credential_pairs'] = json.dumps(credential_pairs)
    else:
        data_key = keymanager.decrypt_datakey(
            _cred.data_key,
            encryption_context={'id': id}
        )
        cipher_version = _cred.cipher_version
        cipher = CipherManager(data_key, cipher_version)
        update['credential_pairs'] = cipher.decrypt(_cred.credential_pairs)
    data_key = keymanager.create_datakey(encryption_context={'id': id})
    cipher = CipherManager(data_key['plaintext'], version=2)
    credential_pairs = cipher.encrypt(update['credential_pairs'])
    update['metadata'] = data.get('metadata', _cred.metadata)
    update['documentation'] = data.get('documentation', _cred.documentation)
    # Enforce documentation, EXCEPT if we are restoring an old revision
    if (not update['documentation'] and
            settings.get('ENFORCE_DOCUMENTATION') and
            not data.get('revision')):
        return jsonify({'error': 'documentation is a required field'}), 400
    # Try to save to the archive
    try:
        Credential(
            id='{0}-{1}'.format(id, revision),
            name=update['name'],
            data_type='archive-credential',
            credential_pairs=credential_pairs,
            metadata=update['metadata'],
            enabled=update['enabled'],
            revision=revision,
            data_key=data_key['ciphertext'],
            cipher_version=2,
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation']
        ).save(id__null=True)
    except PutError as e:
        logging.error(e)
        return jsonify({'error': 'Failed to add credential to archive.'}), 500
    try:
        cred = Credential(
            id=id,
            name=update['name'],
            data_type='credential',
            credential_pairs=credential_pairs,
            metadata=update['metadata'],
            enabled=update['enabled'],
            revision=revision,
            data_key=data_key['ciphertext'],
            cipher_version=2,
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation']
        )
        cred.save()
    except PutError as e:
        logging.error(e)
        return jsonify({'error': 'Failed to update active credential.'}), 500
    if services:
        service_names = [x.id for x in services]
        msg = 'Updated credential "{0}" ({1}); Revision {2}'
        msg = msg.format(cred.name, cred.id, cred.revision)
        graphite.send_event(service_names, msg)
        webhook.send_event('credential_update', service_names, [cred.id])
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': json.loads(cipher.decrypt(cred.credential_pairs)),
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/blind_credentials', methods=['GET'])
@authnz.require_auth
def get_blind_credential_list():
    blind_credentials = []
    for cred in BlindCredential.data_type_date_index.query('blind-credential'):
        blind_credentials.append({
            'id': cred.id,
            'name': cred.name,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })
    return jsonify({'blind_credentials': blind_credentials})


@app.route('/v1/blind_credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_blind_credential(id):
    try:
        cred = BlindCredential.get(id)
    except DoesNotExist:
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (cred.data_type != 'blind-credential' and
            cred.data_type != 'archive-blind-credential'):
        return jsonify({}), 404
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': cred.credential_pairs,
        'credential_keys': list(cred.credential_keys),
        'cipher_type': cred.cipher_type,
        'cipher_version': cred.cipher_version,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'data_key': cred.data_key,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


def _get_latest_credential_revision(id, revision):
    i = revision + 1
    while True:
        _id = '{0}-{1}'.format(id, i)
        try:
            Credential.get(_id)
        except DoesNotExist:
            return i
        i = i + 1


def _get_latest_blind_credential_revision(id, revision):
    i = revision + 1
    while True:
        _id = '{0}-{1}'.format(id, i)
        try:
            BlindCredential.get(_id)
        except DoesNotExist:
            return i
        i = i + 1


@app.route('/v1/archive/blind_credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_archive_blind_credential_revisions(id):
    try:
        cred = BlindCredential.get(id)
    except DoesNotExist:
        return jsonify({}), 404
    if (cred.data_type != 'blind-credential' and
            cred.data_type != 'archive-blind-credential'):
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    revisions = []
    _range = range(1, cred.revision + 1)
    ids = []
    for i in _range:
        ids.append("{0}-{1}".format(id, i))
    for revision in BlindCredential.batch_get(ids):
        revisions.append({
            'id': cred.id,
            'name': cred.name,
            'credential_pairs': cred.credential_pairs,
            'credential_keys': list(cred.credential_keys),
            'cipher_type': cred.cipher_type,
            'cipher_version': cred.cipher_version,
            'metadata': cred.metadata,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'data_key': cred.data_key,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })
    return jsonify({
        'revisions': sorted(
            revisions,
            key=lambda k: k['revision'],
            reverse=True
        )
    })


@app.route('/v1/archive/blind_credentials', methods=['GET'])
@authnz.require_auth
def get_archive_blind_credential_list():
    blind_credentials = []
    for cred in BlindCredential.data_type_date_index.query(
            'archive-blind-credential', scan_index_forward=False):
        blind_credentials.append({
            'id': cred.id,
            'name': cred.name,
            'credential_pairs': cred.credential_pairs,
            'credential_keys': list(cred.credential_keys),
            'cipher_type': cred.cipher_type,
            'cipher_version': cred.cipher_version,
            'metadata': cred.metadata,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'data_key': cred.data_key,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })
    return jsonify({'blind_credentials': blind_credentials})


@app.route('/v1/blind_credentials', methods=['POST'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def create_blind_credential():
    data = request.get_json()
    missing = []
    required_args = ['cipher_version', 'cipher_type', 'credential_pairs',
                     'data_key']
    if settings.get('ENFORCE_DOCUMENTATION'):
        required_args.append('documentation')
    for arg in required_args:
        if not data.get(arg):
            missing.append(arg)
    if missing:
        return jsonify({
            'error': 'The following fields are required: {0}'.format(missing)
        }), 400
    if not isinstance(data['data_key'], dict):
        return jsonify({
            'error': 'data_key must be a dict with a region/key mapping.'
        }), 400
    if not isinstance(data.get('credential_keys', []), list):
        return jsonify({
            'error': 'credential_keys must be a list.'
        }), 400
    if not isinstance(data.get('metadata', {}), dict):
        return jsonify({'error': 'metadata must be a dict'}), 400
    for cred in BlindCredential.data_type_date_index.query(
            'blind-credential', name__eq=data['name']):
        # Conflict, the name already exists
        msg = 'Name already exists. See id: {0}'.format(cred.id)
        return jsonify({'error': msg, 'reference': cred.id}), 409
    # Generate an initial stable ID to allow name changes
    id = str(uuid.uuid4()).replace('-', '')
    # Try to save to the archive
    revision = 1
    cred = BlindCredential(
        id='{0}-{1}'.format(id, revision),
        data_type='archive-blind-credential',
        name=data['name'],
        credential_pairs=data['credential_pairs'],
        credential_keys=data.get('credential_keys'),
        metadata=data.get('metadata'),
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data['data_key'],
        cipher_type=data['cipher_type'],
        cipher_version=data['cipher_version'],
        modified_by=authnz.get_logged_in_user(),
        documentation=data.get('documentation')
    ).save(id__null=True)
    # Make this the current revision
    cred = BlindCredential(
        id=id,
        data_type='blind-credential',
        name=data['name'],
        credential_pairs=data['credential_pairs'],
        credential_keys=data.get('credential_keys'),
        metadata=data.get('metadata'),
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data['data_key'],
        cipher_type=data['cipher_type'],
        cipher_version=data['cipher_version'],
        modified_by=authnz.get_logged_in_user(),
        documentation=data.get('documentation')
    )
    cred.save()
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': cred.credential_pairs,
        'credential_keys': list(cred.credential_keys),
        'cipher_type': cred.cipher_type,
        'cipher_version': cred.cipher_version,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'data_key': cred.data_key,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/blind_credentials/<id>/services', methods=['GET'])
@authnz.require_auth
def get_blind_credential_dependencies(id):
    services = _get_services_for_blind_credential(id)
    _services = [{'id': x.id, 'enabled': x.enabled} for x in services]
    return jsonify({
        'services': _services
    })


@app.route('/v1/blind_credentials/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def update_blind_credential(id):
    try:
        _cred = BlindCredential.get(id)
    except DoesNotExist:
        return jsonify({'error': 'Blind credential not found.'}), 404
    if _cred.data_type != 'blind-credential':
        msg = 'id provided is not a blind-credential.'
        return jsonify({'error': msg}), 400
    data = request.get_json()
    update = {}
    revision = _get_latest_blind_credential_revision(id, _cred.revision)
    update['name'] = data.get('name', _cred.name)
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return jsonify({'error': 'Enabled must be a boolean.'}), 400
        update['enabled'] = data['enabled']
    else:
        update['enabled'] = _cred.enabled
    if not isinstance(data.get('metadata', {}), dict):
        return jsonify({'error': 'metadata must be a dict'}), 400
    services = _get_services_for_blind_credential(id)
    if 'credential_pairs' in data:
        for key in ['data_key', 'cipher_type', 'cipher_version']:
            if key not in data:
                msg = '{0} required when updating credential_pairs.'
                msg = msg.format(key)
                return jsonify({'error': msg}), 400
        update['credential_pairs'] = data['credential_pairs']
        update['credential_keys'] = data.get('credential_keys', [])
        if not isinstance(update['credential_keys'], list):
            return jsonify({
                'error': 'credential_keys must be a list.'
            }), 400
        # Ensure credential keys don't conflicts with pairs from other
        # services
        conflicts = _pair_key_conflicts_for_services(
            id,
            data['credential_keys'],
            services
        )
        if conflicts:
            ret = {
                'error': 'Conflicting key pairs in mapped service.',
                'conflicts': conflicts
            }
            return jsonify(ret), 400
        if not isinstance(data['data_key'], dict):
            return jsonify({
                'error': 'data_key must be a dict with a region/key mapping.'
            }), 400
        update['data_key'] = data['data_key']
        update['cipher_type'] = data['cipher_type']
        update['cipher_version'] = data['cipher_version']
    else:
        update['credential_pairs'] = _cred.credential_pairs
        update['credential_keys'] = _cred.credential_keys
        update['data_key'] = _cred.data_key
        update['cipher_type'] = _cred.cipher_type
        update['cipher_version'] = _cred.cipher_version
    update['metadata'] = data.get('metadata', _cred.metadata)
    update['documentation'] = data.get('documentation', _cred.documentation)
    # Enforce documentation, EXCEPT if we are restoring an old revision
    if (not update['documentation'] and
            settings.get('ENFORCE_DOCUMENTATION') and
            not data.get('revision')):
        return jsonify({'error': 'documentation is a required field'}), 400
    # Try to save to the archive
    try:
        BlindCredential(
            id='{0}-{1}'.format(id, revision),
            data_type='archive-blind-credential',
            name=update['name'],
            credential_pairs=update['credential_pairs'],
            credential_keys=update['credential_keys'],
            metadata=update['metadata'],
            revision=revision,
            enabled=update['enabled'],
            data_key=update['data_key'],
            cipher_type=update['cipher_type'],
            cipher_version=update['cipher_version'],
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation']
        ).save(id__null=True)
    except PutError as e:
        logging.error(e)
        return jsonify(
            {'error': 'Failed to add blind-credential to archive.'}
        ), 500
    try:
        cred = BlindCredential(
            id=id,
            data_type='blind-credential',
            name=update['name'],
            credential_pairs=update['credential_pairs'],
            credential_keys=update['credential_keys'],
            metadata=update['metadata'],
            revision=revision,
            enabled=update['enabled'],
            data_key=update['data_key'],
            cipher_type=update['cipher_type'],
            cipher_version=update['cipher_version'],
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation']
        )
        cred.save()
    except PutError as e:
        logging.error(e)
        return jsonify(
            {'error': 'Failed to update active blind-credential.'}
        ), 500
    if services:
        service_names = [x.id for x in services]
        msg = 'Updated credential "{0}" ({1}); Revision {2}'
        msg = msg.format(cred.name, cred.id, cred.revision)
        graphite.send_event(service_names, msg)
        webhook.send_event('blind_credential_update', service_names, [cred.id])
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': cred.credential_pairs,
        'credential_keys': list(cred.credential_keys),
        'cipher_type': cred.cipher_type,
        'cipher_version': cred.cipher_version,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'data_key': cred.data_key,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/value_generator', methods=['GET'])
def generate_value():
    value = kms_client.generate_random(NumberOfBytes=128)['Plaintext']
    value = base64.urlsafe_b64encode(value)
    value = re.sub('[\W_]+', '', value)
    if len(value) > VALUE_LENGTH:
        value = value[:VALUE_LENGTH]
    return jsonify({'value': value})
