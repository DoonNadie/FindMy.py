"""Offline regressions for the maintained fork; no Apple accounts or network needed."""
import asyncio
import json
import plistlib
import ssl
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from findmy import KeyPair
from findmy.errors import ReauthenticationRequiredError, UnhandledProtocolError
from findmy.reports.account import AsyncAppleAccount
from findmy.reports.anisette import BaseAnisetteProvider, ExternalAnisetteProvider, LocalAnisetteProvider
from findmy.reports.state import LoginState
from findmy.util.http import HttpResponse, HttpSession
from findmy.util.tls import apple_trust_context, _verified_root, TlsError


class DummyProvider(BaseAnisetteProvider):
    otp = 'test-otp'
    machine = 'test-machine'
    def to_json(self, dst=None):
        return {'type': 'external'}
    @classmethod
    def from_json(cls, val):
        return cls()
    async def close(self):
        pass


def raw_identity():
    return {'X-Apple-I-MD': 'otp', 'X-Apple-I-MD-M': 'machine',
            'X-Apple-I-MD-LU': 'original-lu', 'X-MMe-Device-Id': 'original-device',
            'X-MMe-Client-Info': 'test native identity'}


class AccountTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.account = AsyncAppleAccount(DummyProvider())
        self.addAsyncCleanup(self.account.close)

    async def test_password_never_serialized(self):
        self.account._password = 'sentinel-password-do-not-save'
        state = self.account.to_json()
        self.assertIsNone(state['account']['password'])
        self.assertNotIn('sentinel-password', json.dumps(state))
        self.account.forget_password()
        self.assertIsNone(self.account._password)

    async def test_legacy_password_not_restored(self):
        state = self.account.to_json()
        state['account']['password'] = 'old-plaintext-password'
        restored = AsyncAppleAccount(DummyProvider(), state_info=state)
        self.addAsyncCleanup(restored.close)
        self.assertIsNone(restored._password)

    async def test_numeric_zero_delegate_status(self):
        self.account._username = 'offline@example.invalid'
        for body in [
            {'dsid': 'test', 'delegates': {'com.apple.mobileme': {'status': 0, 'service-data': {'tokens': {'searchPartyToken': 'test-token'}}}}},
            {'dsid': 'test', 'status': 0, 'delegates': {'com.apple.mobileme': {'service-data': {'tokens': {'searchPartyToken': 'test-token'}}}}},
            {'dsid': 'test', 'status': 1, 'delegates': {'com.apple.mobileme': {'status': 0, 'service-data': {'tokens': {'searchPartyToken': 'test-token'}}}}},
        ]:
            self.account._set_login_state(LoginState.AUTHENTICATED, {'idms_pet': 'token', 'adsid': 'id'})
            self.account._http.post = AsyncMock(return_value=HttpResponse(200, plistlib.dumps(body)))
            self.assertEqual(await self.account._login_mobileme(), LoginState.LOGGED_IN)

    async def test_delegate_error_does_not_echo_server_text(self):
        self.account._username = 'offline@example.invalid'
        for status in [1, None, 'secret-in-status']:
            self.account._set_login_state(LoginState.AUTHENTICATED, {'idms_pet': 'token', 'adsid': 'id'})
            body = {'status': status, 'status-message': 'server-secret', 'delegates': {}}
            self.account._http.post = AsyncMock(return_value=HttpResponse(200, plistlib.dumps(body) if status is not None else plistlib.dumps({'delegates': {}})))
            with self.assertRaises(UnhandledProtocolError) as result:
                await self.account._login_mobileme()
            self.assertNotIn('secret', str(result.exception))

    async def test_expired_session_requires_interactive_auth_without_password(self):
        self.account._set_login_state(LoginState.LOGGED_IN, {'dsid': 'id', 'mobileme_data': {'tokens': {'searchPartyToken': 'test-token'}}})
        self.account._http.post = AsyncMock(return_value=HttpResponse(401, b''))
        with self.assertRaises(ReauthenticationRequiredError):
            await self.account.fetch_raw_reports([])


class IdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_external_identity_preserved(self):
        provider = ExternalAnisetteProvider(AsyncMock(return_value=raw_identity()), user_agent='native-agent')
        self.addAsyncCleanup(provider.close)
        headers = await provider.get_mobileme_headers('alternative-user', 'alternative-device')
        self.assertEqual(headers['X-Apple-I-MD-LU'], 'original-lu')
        self.assertEqual(headers['X-Mme-Device-Id'], 'original-device')
        self.assertEqual(headers['X-Mme-Client-Info'], 'test native identity')
        self.assertEqual(headers['User-Agent'], 'native-agent')
        self.assertNotIn('otp', json.dumps(provider.to_json()))

    async def test_invalid_identity_stops_before_network(self):
        for changes in [{'X-Apple-I-MD': ''}, {'Authorization': 'secret'},
                        {'x-apple-i-md': 'duplicate'}, {'X-Apple-I-MD': 'a\rb'},
                        {'X-Apple-I-MD-M': None}]:
            data = raw_identity();data.update(changes)
            provider = ExternalAnisetteProvider(AsyncMock(return_value=data), user_agent='native-agent')
            self.addAsyncCleanup(provider.close)
            with self.assertRaises(ValueError):
                await provider.get_headers('id', 'device')

    async def test_external_loader_must_be_supplied_explicitly(self):
        with self.assertRaises(ValueError):
            ExternalAnisetteProvider.from_json({'type': 'external'})

    async def test_missing_local_libraries_never_download(self):
        provider = LocalAnisetteProvider(libs_path=Path('/no-such-reviewed-file.zip'))
        self.addAsyncCleanup(provider.close)
        with patch('anisette.Anisette.load') as loader:
            with self.assertRaises(ValueError):
                await provider.get_headers('id', 'device')
            loader.assert_not_called()


class Content:
    def __init__(self, content): self.content = content
    async def iter_chunked(self, size):
        for i in range(0, len(self.content), size): yield self.content[i:i+size]

class Response:
    def __init__(self, status=200, content=b'ok'):
        self.status=status;self.content=Content(content)
    async def __aenter__(self): return self
    async def __aexit__(self, *args): return False

class HttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_policy_blocks_unsafe_urls_before_opening_session(self):
        session = HttpSession(apple_only=True)
        self.addAsyncCleanup(session.close)
        session._get_session = AsyncMock()
        for url in ['http://gsa.apple.com/', 'https://apple.com.evil.invalid/',
                    'https://evilapple.com/', 'https://evil.invalid/',
                    'https://user:password@gsa.apple.com/', 'https://gsa.apple.com:444/',
                    'https://gsa.apple.com/#fragment', 'https://gsa.apple.com/\nsecret']:
            with self.assertRaises(ValueError): await session.get(url)
        session._get_session.assert_not_called()
        for url in ['https://gsa.apple.com/', 'https://gateway.icloud.com/', 'https://apple.com/']:
            session.validate_url(url)

    async def test_redirects_disabled_and_basic_auth_encoded(self):
        session=HttpSession(apple_only=True);self.addAsyncCleanup(session.close)
        fake=AsyncMock();fake.request.return_value=Response()
        session._get_session=AsyncMock(return_value=fake)
        self.assertEqual((await session.post('https://gsa.apple.com/',auth=('user','pass'))).status_code,200)
        options=fake.request.call_args.kwargs
        self.assertFalse(options['allow_redirects'])
        self.assertNotIn('auth', options)
        self.assertEqual(options['headers']['Authorization'], 'Basic dXNlcjpwYXNz')
        self.assertEqual(options['ssl'].verify_mode,ssl.CERT_REQUIRED)
        fake.request.return_value=Response(302)
        with self.assertRaises(ValueError): await session.get('https://gsa.apple.com/')

    async def test_size_limit_and_conflicting_auth(self):
        session=HttpSession(apple_only=True,max_response_bytes=3);self.addAsyncCleanup(session.close)
        fake=AsyncMock();fake.request.return_value=Response(content=b'abcd')
        session._get_session=AsyncMock(return_value=fake)
        with self.assertRaises(ValueError): await session.get('https://gsa.apple.com/')
        with self.assertRaises(ValueError):
            await session.get('https://gsa.apple.com/',auth=('u','p'),headers={'authorization':'secret'})


class BaselineTests(unittest.TestCase):
    def test_one_hundred_keypairs(self):
        for _ in range(100):
            key=KeyPair.new()
            self.assertEqual(len(key.private_key_bytes),28)
            self.assertEqual(len(key.adv_key_bytes),28)
            self.assertEqual(len(key.hashed_adv_key_bytes),32)

    def test_tls_verifies_and_root_is_checked(self):
        context=apple_trust_context()
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        with patch('findmy.util.tls.APPLE_ROOT_CA_SHA256',b'\0'*32):
            with self.assertRaises(TlsError): _verified_root()

class AdditionalSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_redirect_response_is_rejected(self):
        session=HttpSession(apple_only=True);self.addAsyncCleanup(session.close)
        fake=AsyncMock();fake.request.return_value=Response(307)
        session._get_session=AsyncMock(return_value=fake)
        with self.assertRaisesRegex(ValueError, 'redirect'):
            await session.post('https://gsa.apple.com/',data=b'sensitive')
        self.assertEqual(fake.request.await_count,1)

    async def test_oversized_response_is_rejected(self):
        session=HttpSession(apple_only=True,max_response_bytes=2);self.addAsyncCleanup(session.close)
        fake=AsyncMock();fake.request.return_value=Response(200,b'123')
        session._get_session=AsyncMock(return_value=fake)
        with self.assertRaisesRegex(ValueError, 'size limit'):
            await session.get('https://gsa.apple.com/')

    async def test_apple_tls_cannot_be_disabled(self):
        for options in [{'verify_tls':False},{'allow_insecure_http':True}]:
            with self.assertRaises(ValueError): HttpSession(apple_only=True,**options)
        self.assertEqual(apple_trust_context().verify_mode,ssl.CERT_REQUIRED)
        self.assertTrue(apple_trust_context().check_hostname)

    async def test_transport_exception_is_redacted(self):
        import aiohttp
        session=HttpSession();self.addAsyncCleanup(session.close)
        fake=AsyncMock();fake.request.side_effect=aiohttp.ClientError('secret-url-token')
        session._get_session=AsyncMock(return_value=fake)
        with self.assertRaises(RuntimeError) as result:
            await session.get('https://example.invalid/')
        self.assertNotIn('secret-url-token',str(result.exception))

    async def test_encrypted_account_roundtrip_has_no_password(self):
        import tempfile
        from findmy.storage import EncryptedStateStore
        with tempfile.TemporaryDirectory() as tmp:
            store=EncryptedStateStore(Path(tmp).resolve()/'state',bytes(range(32)))
            account=AsyncAppleAccount(DummyProvider());self.addAsyncCleanup(account.close)
            account._password='sentinel-never-save'
            account.save_encrypted(store)
            saved=store.read_json('account.json')
            self.assertIsNone(saved['account']['password'])
            self.assertNotIn('sentinel-never-save',json.dumps(saved))

    async def test_incomplete_builtin_identity_rejected(self):
        provider=DummyProvider();provider.otp='';self.addAsyncCleanup(provider.close)
        with self.assertRaises(ValueError): await provider.get_headers('id','device')

    async def test_library_loader_fallback_cannot_download(self):
        import tempfile
        from anisette._ani_provider import AnisetteProvider
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'local.zip';path.write_bytes(b'not a valid library bundle')
            provider=LocalAnisetteProvider(libs_path=path);self.addAsyncCleanup(provider.close)
            def require_fallback(*args, **kwargs):
                return kwargs['fs_fallback']()
            with patch.object(AnisetteProvider,'load',side_effect=require_fallback):
                with self.assertRaisesRegex(RuntimeError,'downloads are disabled'):
                    await provider.get_headers('id','device')
            self.assertEqual(path.read_bytes(),b'not a valid library bundle')


class DelegateStructureTests(unittest.IsolatedAsyncioTestCase):
    async def test_incomplete_delegate_does_not_mark_session_logged_in(self):
        account=AsyncAppleAccount(DummyProvider());self.addAsyncCleanup(account.close)
        account._username='offline@example.invalid'
        for delegates in [[], {'com.apple.mobileme': []},
                          {'com.apple.mobileme': {'status': 0, 'service-data': {}}},
                          {'com.apple.mobileme': {'status': 0, 'service-data': {'tokens': []}}},
                          {'com.apple.mobileme': {'status': 0, 'service-data': {'tokens': {'searchPartyToken': ''}}}}]:
            account._set_login_state(LoginState.AUTHENTICATED,{'adsid':'id','idms_pet':'token'})
            account._http.post=AsyncMock(return_value=HttpResponse(200,plistlib.dumps({'dsid':'id','delegates':delegates})))
            with self.assertRaises(UnhandledProtocolError): await account._login_mobileme()
            self.assertEqual(account.login_state,LoginState.AUTHENTICATED)
