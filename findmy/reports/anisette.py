"""Module for Anisette header providers."""

from __future__ import annotations

import asyncio
import base64
import io
import locale
import logging
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from contextlib import ExitStack
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Literal, TypedDict

from anisette import Anisette, AnisetteHeaders
from typing_extensions import Required, override

from findmy import util

logger = logging.getLogger(__name__)


class RemoteAnisetteMapping(TypedDict, total=False):
    """JSON mapping representing state of a remote Anisette provider."""

    type: Required[Literal["aniRemote"]]
    url: Required[str]

    allow_unverified_https: bool
    """
    Only written when it is true, so existing files stay valid and unchanged.

    It has to be written at all because a provider is reconstructed from this: a user whose
    own server has a self-signed certificate would otherwise find that saving and reloading
    an account silently turned their working setup into a failing one.
    """


class LocalAnisetteMapping(TypedDict):
    """JSON mapping representing state of a local Anisette provider."""

    type: Literal["aniLocal"]
    prov_data: str | None


AnisetteMapping = RemoteAnisetteMapping | LocalAnisetteMapping


def get_provider_from_mapping(
    mapping: AnisetteMapping,
    *,
    libs_path: str | Path | None = None,
) -> RemoteAnisetteProvider | LocalAnisetteProvider:
    """Get the correct Anisette provider instance from saved JSON data."""
    if mapping["type"] == "aniRemote":
        return RemoteAnisetteProvider.from_json(mapping)
    if mapping["type"] == "aniLocal":
        return LocalAnisetteProvider.from_json(mapping, libs_path=libs_path)
    msg = "Unknown or external Anisette provider; supply a provider explicitly"
    raise ValueError(msg)


class BaseAnisetteProvider(util.abc.Closable, util.abc.Serializable, ABC):
    """
    Abstract base class for Anisette providers.

    Generously derived from https://github.com/nythepegasus/grandslam/blob/main/src/grandslam/gsa.py#L41.
    """

    @property
    @abstractmethod
    def otp(self) -> str:
        """A seemingly random base64 string containing 28 bytes."""
        raise NotImplementedError

    @property
    @abstractmethod
    def machine(self) -> str:
        """A base64 encoded string of 60 'random' bytes."""
        raise NotImplementedError

    @property
    def timestamp(self) -> str:
        """Current timestamp in ISO 8601 format."""
        return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat() + "Z"

    @property
    def timezone(self) -> str:
        """Abbreviation of the timezone of the device."""
        return str(datetime.now().astimezone().tzinfo)

    @property
    def locale(self) -> str:
        """Locale of the device (e.g. en_US)."""
        return locale.getdefaultlocale()[0] or "en_US"

    @property
    def router(self) -> str:
        """
        A number, either 17106176 or 50660608.

        It doesn't seem to matter which one we use.
        - 17106176 is used by Sideloadly and Provision (android) based servers.
        - 50660608 is used by Windows iCloud based servers.
        """
        return "17106176"

    @property
    def client(self) -> str:
        """
        Client string.

        The format is as follows:
        <%MODEL%> <%OS%;%MAJOR%.%MINOR%(%SPMAJOR%,%SPMINOR%);%BUILD%>
         <%AUTHKIT_BUNDLE_ID%/%AUTHKIT_VERSION% (%APP_BUNDLE_ID%/%APP_VERSION%)>

        Where:
            MODEL: The model of the device (e.g. MacBookPro15,1 or 'PC'
            OS: The OS of the device (e.g. Mac OS X or Windows)
            MAJOR: The major version of the OS (e.g. 10)
            MINOR: The minor version of the OS (e.g. 15)
            SPMAJOR: The major version of the service pack (e.g. 0) (Windows only)
            SPMINOR: The minor version of the service pack (e.g. 0) (Windows only)
            BUILD: The build number of the OS (e.g. 19C57)
            AUTHKIT_BUNDLE_ID: The bundle ID of the AuthKit framework (e.g. com.apple.AuthKit)
            AUTHKIT_VERSION: The version of the AuthKit framework (e.g. 1)
            APP_BUNDLE_ID: The bundle ID of the app (e.g. com.apple.akd)
            APP_VERSION: The version of the app (e.g. 1.0)

        The app must not be reported as `com.apple.dt.Xcode`. Since early September 2026
        Apple's edge refuses any Grand Slam request whose client info names Xcode, before
        any credential is examined: a 190-byte HTML page from `Server: Apple` rather than
        a GSA plist, which surfaces as HTTP 503. `com.apple.akd` is the daemon that
        actually performs this request on macOS, and is answered normally.
        """
        return "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """
        Generate a complete dictionary of Anisette headers.

        Consider using :meth:`BaseAppleAccount.get_anisette_headers` instead.
        """
        if not self.otp or not self.machine:
            raise ValueError("Anisette identity is incomplete; refusing authentication")
        headers = {
            # Current Time
            "X-Apple-I-Client-Time": self.timestamp,
            "X-Apple-I-TimeZone": self.timezone,
            # Locale
            "loc": self.locale,
            "X-Apple-Locale": self.locale,
            # 'One Time Password'
            "X-Apple-I-MD": self.otp,
            # 'Local User ID'
            "X-Apple-I-MD-LU": base64.b64encode(str(user_id).encode()).decode(),
            # 'Machine ID'
            "X-Apple-I-MD-M": self.machine,
            # 'Routing Info', some implementations convert this to an integer
            "X-Apple-I-MD-RINFO": self.router,
            # 'Device Unique Identifier'
            "X-Mme-Device-Id": str(device_id).upper(),
            # 'Device Serial Number'
            "X-Apple-I-SRL-NO": serial,
        }

        if with_client_info:
            headers["X-Mme-Client-Info"] = self.client
            headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
            headers["X-Xcode-Version"] = "11.2 (11B41)"

        return headers

    async def get_mobileme_headers(self, user_id: str, device_id: str) -> dict[str, str]:
        """Build delegate headers; providers may preserve a coherent native identity."""
        headers = {
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8>"
            " <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
        }
        headers.update(await self.get_headers(user_id, device_id))
        return headers

    async def get_cpd(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
    ) -> dict[str, str]:
        """
        Generate a complete dictionary of CPD data.

        Intended for internal use.
        """
        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        cpd.update(await self.get_headers(user_id, device_id, serial))

        return cpd


class RemoteAnisetteProvider(BaseAnisetteProvider, util.abc.Serializable[RemoteAnisetteMapping]):
    """Anisette provider. Fetches headers from a remote Anisette server."""

    _ANISETTE_DATA_VALID_FOR = 30

    def __init__(self, server_url: str, *, allow_unverified_https: bool = False) -> None:
        """
        Initialize the provider with URL to te remote server.

        :param server_url: Where to fetch Anisette headers from.
        :param allow_unverified_https: Skip certificate verification for **this server
            only**. Off by default, and the only switch of its kind in the library.

            It exists for one case: an Anisette server you run yourself, over HTTPS, with a
            self-signed certificate. A server reached over plain `http://` needs nothing --
            there is no TLS to verify -- and a public server with a real certificate needs
            nothing either. Everything Apple-facing is verified regardless of this flag; it
            reaches no request but the one to this URL.

            Turning it on means anything on the network path to that server can read and
            alter the Anisette data your logins are built from.
        """
        super().__init__()

        self._server_url = server_url
        self._allow_unverified_https = allow_unverified_https

        self._http = util.http.HttpSession(verify_tls=not allow_unverified_https)

        self._anisette_data: dict[str, str] | None = None
        self._anisette_data_expires_at: float = 0
        self._closed = False

    @override
    def to_json(self, dst: str | Path | io.TextIOBase | None = None, /) -> RemoteAnisetteMapping:
        """See :meth:`BaseAnisetteProvider.serialize`."""
        state: RemoteAnisetteMapping = {
            "type": "aniRemote",
            "url": self._server_url,
        }
        if self._allow_unverified_https:
            state["allow_unverified_https"] = True

        return util.files.save_and_return_json(state, dst)

    @classmethod
    @override
    def from_json(
        cls, val: str | Path | io.TextIOBase | io.BufferedIOBase | RemoteAnisetteMapping
    ) -> RemoteAnisetteProvider:
        """See :meth:`BaseAnisetteProvider.deserialize`."""
        val = util.files.read_data_json(val)

        assert val["type"] == "aniRemote"

        server_url = val["url"]

        return cls(
            server_url,
            allow_unverified_https=val.get("allow_unverified_https", False),
        )

    @property
    @override
    def otp(self) -> str:
        """See :meth:`BaseAnisetteProvider.otp`."""
        otp = (self._anisette_data or {}).get("X-Apple-I-MD")
        if otp is None:
            logger.warning("X-Apple-I-MD header not found! Returning fallback...")
        return otp or ""

    @property
    @override
    def machine(self) -> str:
        """See :meth:`BaseAnisetteProvider.machine`."""
        machine = (self._anisette_data or {}).get("X-Apple-I-MD-M")
        if machine is None:
            logger.warning("X-Apple-I-MD-M header not found! Returning fallback...")
        return machine or ""

    @override
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """See :meth::meth:`BaseAnisetteProvider.get_headers`."""
        if self._closed:
            msg = "RemoteAnisetteProvider has been closed and cannot be used"
            raise RuntimeError(msg)

        if self._anisette_data is None or time.time() >= self._anisette_data_expires_at:
            logger.info("Fetching remote Anisette data")

            r = await self._http.get(self._server_url, auto_retry=True)
            self._anisette_data = r.json()
            self._anisette_data_expires_at = time.time() + self._ANISETTE_DATA_VALID_FOR

        return await super().get_headers(user_id, device_id, serial, with_client_info)

    @override
    async def close(self) -> None:
        """See :meth:`AnisetteProvider.close`."""
        if self._closed:
            return  # Already closed, make it idempotent

        self._closed = True

        try:
            await self._http.close()
        except (RuntimeError, OSError, ConnectionError) as e:
            logger.warning("Error closing anisette HTTP session: %s", e)


class LocalAnisetteProvider(BaseAnisetteProvider, util.abc.Serializable[LocalAnisetteMapping]):
    """Local anisette provider using the `anisette` library."""

    def __init__(
        self,
        *,
        state_blob: BytesIO | None = None,
        libs_path: str | Path | None = None,
    ) -> None:
        """Initialize the provider."""
        super().__init__()

        if isinstance(libs_path, str):
            libs_path = Path(libs_path)

        # we do not yet initialize Anisette in order to prevent blocking the event loop,
        # since the anisette library will download the required libraries synchronously.
        self._ani: Anisette | None = None

        self._ani_data: AnisetteHeaders | None = None
        self._libs_path: Path | None = libs_path
        self._state_blob: BytesIO | None = state_blob

    @property
    def _is_new_session(self) -> bool:
        return self._state_blob is None

    async def _get_ani(self) -> Anisette:
        if self._ani is not None:
            return self._ani

        if self._libs_path is None or not self._libs_path.is_file() or self._libs_path.is_symlink():
            raise ValueError("Provide a reviewed local Anisette library file; downloads are disabled")

        files: list[BinaryIO | Path] = []
        if self._state_blob is not None:
            files.append(self._state_blob)
        if self._libs_path is not None and self._libs_path.exists():
            files.append(self._libs_path)

        loop = asyncio.get_running_loop()
        def load_local() -> Anisette:
            # Anisette 1.2.x's public load() silently downloads missing libraries.
            # Supply a fail-closed fallback directly instead (version-bound adapter).
            from anisette._ani_provider import AnisetteProvider

            def no_download() -> object:
                raise RuntimeError("Implicit Anisette library downloads are disabled")

            with ExitStack() as stack:
                streams = [stack.enter_context(f.open("rb")) if isinstance(f, Path) else f
                           for f in files]
                provider = AnisetteProvider.load(*streams, fs_fallback=no_download)
            return Anisette(provider)

        ani = await loop.run_in_executor(None, load_local)
        is_provisioned = await loop.run_in_executor(None, lambda: ani.is_provisioned)

        if not self._is_new_session and not is_provisioned:
            logger.warning(
                "The Anisette state that was loaded has not yet been provisioned. "
                "Was the previous session saved properly?",
            )

        # pre-provision to ensure that the VM has initialized
        await loop.run_in_executor(None, ani.provision)

        self._ani = ani
        return ani

    @override
    def to_json(self, dst: str | Path | io.TextIOBase | None = None, /) -> LocalAnisetteMapping:
        """See :meth:`BaseAnisetteProvider.serialize`."""
        if self._ani is None:
            # Anisette has not been called yet, so the future has not yet resolved.
            # We don't want to wait here, so we just return the original state blob.
            # If the state blob is None, this means we have a new session that has not
            # been provisioned yet, so we will not save the provisioning data.
            if self._state_blob is None:
                prov_data = None
            else:
                prov_data = base64.b64encode(self._state_blob.getvalue()).decode("utf-8")
        else:
            # Anisette has been initialized, so we can save the provisioning data.
            with BytesIO() as buf:
                self._ani.save_provisioning(buf)
                prov_data = base64.b64encode(buf.getvalue()).decode("utf-8")

        return util.files.save_and_return_json(
            {
                "type": "aniLocal",
                "prov_data": prov_data,
            },
            dst,
        )

    @classmethod
    @override
    def from_json(
        cls,
        val: str | Path | io.TextIOBase | io.BufferedIOBase | LocalAnisetteMapping,
        *,
        libs_path: str | Path | None = None,
    ) -> LocalAnisetteProvider:
        """See :meth:`BaseAnisetteProvider.deserialize`."""
        val = util.files.read_data_json(val)

        assert val["type"] == "aniLocal"

        prov_data = val["prov_data"]
        state_blob = None if prov_data is None else BytesIO(base64.b64decode(prov_data))

        return cls(state_blob=state_blob, libs_path=libs_path)

    @override
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str = "0",
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """See :meth:`BaseAnisetteProvider.get_headers`."""
        ani = await self._get_ani()

        # run in executor to prevent blocking the event loop,
        # since get_data may make blocking network requests.
        loop = asyncio.get_running_loop()
        self._ani_data = await loop.run_in_executor(None, ani.get_data)

        return await super().get_headers(user_id, device_id, serial, with_client_info)

    @property
    @override
    def otp(self) -> str:
        """See :meth:`BaseAnisetteProvider.otp`."""
        machine = (self._ani_data or {}).get("X-Apple-I-MD")
        if machine is None:
            logger.warning("X-Apple-I-MD header not found! Returning fallback...")
        return machine or ""

    @property
    @override
    def machine(self) -> str:
        """See :meth:`BaseAnisetteProvider.machine`."""
        machine = (self._ani_data or {}).get("X-Apple-I-MD-M")
        if machine is None:
            logger.warning("X-Apple-I-MD-M header not found! Returning fallback...")
        return machine or ""

    @override
    async def close(self) -> None:
        """See :meth:`BaseAnisetteProvider.close`."""


class ExternalAnisetteProvider(BaseAnisetteProvider):
    """Use an explicit caller-supplied async header loader, preserving its identity.

    No subprocess, server, download or secret persistence is performed by this provider.
    Restore account state by supplying this provider explicitly to AsyncAppleAccount.
    The caller is responsible for reviewing its loader and storing state securely.
    """

    def __init__(self, loader: Callable[[], Awaitable[dict[str, str]]], *, user_agent: str) -> None:
        super().__init__()
        self._loader = loader
        self._headers: dict[str, str] = {}
        self._user_agent = user_agent
        if not user_agent or any(ord(c) < 32 or ord(c) == 127 for c in user_agent):
            raise ValueError("Invalid user agent")

    @property
    def otp(self) -> str:
        return self._headers.get("X-Apple-I-MD", "")

    @property
    def machine(self) -> str:
        return self._headers.get("X-Apple-I-MD-M", "")

    @property
    def client(self) -> str:
        return self._headers.get("X-Mme-Client-Info", "")

    async def get_headers(self, user_id: str, device_id: str, serial: str = "0",
                          with_client_info: bool = False) -> dict[str, str]:
        raw = await self._loader()
        if not isinstance(raw, dict):
            raise ValueError("External Anisette loader must return a header mapping")
        canonical = {
            name.lower(): name for name in (
                "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU",
                "X-Apple-I-MD-RINFO", "X-Mme-Device-Id", "X-Mme-Client-Info",
                "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale",
                "X-Apple-I-SRL-NO", "loc",
            )
        }
        headers: dict[str, str] = {}
        for name, value in raw.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError("Invalid external Anisette headers")
            key = canonical.get(name.lower())
            if key is None:
                # Do not let a loader inject Authorization, Host, cookies or account IDs.
                raise ValueError("Unexpected external Anisette header")
            if key in headers or not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError("Empty, duplicate or invalid external Anisette header")
            headers[key] = value
        required = ("X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU",
                    "X-Mme-Device-Id", "X-Mme-Client-Info")
        if any(key not in headers for key in required):
            raise ValueError("External Anisette identity is incomplete")
        self._headers = headers
        return dict(headers)

    async def get_mobileme_headers(self, user_id: str, device_id: str) -> dict[str, str]:
        headers = await self.get_headers(user_id, device_id)
        headers["User-Agent"] = self._user_agent
        return headers

    def to_json(self, dst: str | Path | io.TextIOBase | None = None, /) -> dict:
        return util.files.save_and_return_json({"type": "external"}, dst)

    @classmethod
    def from_json(cls, val: object) -> ExternalAnisetteProvider:
        raise ValueError("Supply an explicit trusted header loader when restoring account state")

    async def close(self) -> None:
        self._headers.clear()
